// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

const (
	// probeConfirmTimeout is how long the region an address names gets
	// to answer on its own before the search widens to the rest of the
	// map. A miss here is not fatal: the widened search probes that
	// region again alongside the others.
	probeConfirmTimeout = 3 * time.Second

	// probeSearchTimeout bounds the widened search.
	probeSearchTimeout = 15 * time.Second

	// probeSettle is how long a search waits, after the first region
	// answers, for one of the regions the address already names to
	// answer too. A server reachable in several regions would otherwise
	// have its address rewritten to whichever relay happened to reply
	// first.
	probeSettle = 250 * time.Millisecond

	// probeMeowInterval is how often a probe re-sends its meow. It is
	// shorter than meowRetryInterval because a probe has only
	// probeConfirmTimeout to get an answer, and the first meow after
	// connecting is often dropped while the server's own DERP connection
	// is still coming up.
	probeMeowInterval = 250 * time.Millisecond

	// probeStagger spaces out the connections a widened search opens, so
	// a large DERP map doesn't produce one burst of TLS handshakes.
	probeStagger = 100 * time.Millisecond

	// maxProbeRegions caps how many regions one search probes. Today's
	// tailcat DERP map has four; the cap is here so that a much larger
	// map can't turn one stale address into a storm.
	maxProbeRegions = 8
)

// DiscoverRegion returns an address equivalent to addr but naming the
// DERP region where the server is reachable now, for a server that has
// moved since addr was published. A server started with "genkey
// --region=auto" re-picks its region by latency at every startup, so an
// address handed out earlier can name a region it has since left; the
// client then just times out. The server's identity travels in the
// address and doesn't change, so DiscoverRegion keeps it and asks each
// candidate region whether the server is there, using the same meow
// handshake a real connection makes.
//
// If the server answers in the region addr already names, addr is
// returned unchanged.
//
// clientKey must be the node key the caller will connect with: a server
// started with --allow ignores meows from any other key, so discovery with
// a throwaway key would find nothing.
//
// The opts may contain any of the following types:
//   - [DERPMapURL]: fetch the DERP map from an alternate URL instead
//     of [DefaultDERPMapURL].
//   - [*tailcfg.DERPMap]: search the provided DERP map instead of
//     fetching one over the network.
//   - [DERPMapCache]: cache fetched DERP maps (defaults to a
//     process-wide in-memory cache).
//   - [logger.Logf]: where to log the progress of the search.
func DiscoverRegion(ctx context.Context, addr Addr, clientKey key.NodePrivate, opts ...any) (Addr, error) {
	ci, err := ParseAddr(addr)
	if err != nil {
		return "", err
	}
	if ci.ServerDiscoPublic.IsZero() {
		return "", errors.New("legacy server address lacks a separate disco key; generate a new address with an updated tailcat server")
	}

	fetchURL := DefaultDERPMapURL
	var dm *tailcfg.DERPMap
	var cache DERPMapCache
	logf := logger.Discard
	for _, opt := range opts {
		switch v := opt.(type) {
		case DERPMapURL:
			fetchURL = string(v)
		case *tailcfg.DERPMap:
			dm = v
		case DERPMapCache:
			cache = v
		case logger.Logf:
			logf = v
		default:
			return "", fmt.Errorf("unknown DiscoverRegion option type %T", opt)
		}
	}
	getMap := func() (*tailcfg.DERPMap, error) {
		if dm == nil {
			dm, err = fetchDERPMap(ctx, fetchURL, "client", cache)
			if err != nil {
				return nil, fmt.Errorf("fetching DERP map to search for the server: %w", err)
			}
		}
		return dm, nil
	}

	// derphttp dials through netns, which createEngine disables for the
	// real connection; probe the same way it will.
	netns.SetEnabled(false)
	p := &regionProber{
		netMon:    netmon.NewStatic(),
		logf:      logf,
		priv:      clientKey,
		serverPub: ci.ServerPublic.NodePublic,
		// The probe registers with the server exactly as the real client
		// will: onMeow keeps the disco key from the first meow it sees and
		// ignores later ones, so a probe presenting a different key would
		// leave the server with an entry the real client can't correct.
		pkt: EncodeMeowPing(clientKey.Public(), DiscoPublicForNode(clientKey).DiscoPublic),
	}

	named, embedded := ci.Region, len(ci.Region) > 0
	if !embedded && ci.RegionID > 0 {
		m, err := getMap()
		if err != nil {
			return "", err
		}
		if r, ok := m.Regions[ci.RegionID]; ok {
			named = []*tailcfg.DERPRegion{r}
		}
	}
	var namedCands []probeCandidate
	for _, r := range named {
		namedCands = append(namedCands, probeCandidate{r, true})
	}
	if len(namedCands) > 0 {
		if got := p.probe(ctx, namedCands, probeConfirmTimeout); len(got) > 0 {
			return addr, nil
		}
		logf("auto-region: no response in %v; searching the rest of the DERP map", regionList(namedCands))
	}

	m, err := getMap()
	if err != nil {
		return "", err
	}
	cands := searchCandidates(m, namedCands, embedded)
	if len(cands) == 0 {
		return "", fmt.Errorf("no DERP regions to search in %v", fetchURL)
	}
	got := p.probe(ctx, cands, probeSearchTimeout)
	if len(got) == 0 {
		// A server ignores meows from a client that isn't on its --allow
		// list in exactly the way an absent server does, so name both.
		return "", fmt.Errorf("no response from the server in DERP regions %v; it may be on a relay not listed in %v, or this client's key may not be on its --allow list",
			regionList(cands), fetchURL)
	}
	// The search re-probes the regions the address names, so a confirm
	// that merely ran slow lands here rather than costing the connection.
	if got[0].named {
		return addr, nil
	}
	// Multi-region servers are a possibility (tailcat#7), so probe reports
	// every region that answered; today the client connects to one, and
	// the short RegionID form is the only one whose region ID survives a
	// round trip through an [Addr].
	ci.Region = nil
	ci.RegionID = got[0].reg.RegionID
	return ci.Addr(), nil
}

// probeCandidate is a region to probe, and whether the address being
// resolved already names it.
type probeCandidate struct {
	reg   *tailcfg.DERPRegion
	named bool
}

// searchCandidates returns the regions to probe for a server that did
// not answer in the regions its address named: those regions first, then
// the rest of dm by ascending ID.
//
// The named regions are probed again rather than skipped. A confirm stage
// that timed out only because the relay was slow to come up would
// otherwise report a server that never moved as moved, or fail outright
// when nothing else answers.
//
// embedded says whether named came from the address rather than from dm.
// An embedded address's regions carry no usable ID — [ConnInfo.Addr]
// strips it and [ParseAddr] synthesizes 1..N in its place — so a dm
// region is recognized as one of them by relay hostname instead. A
// mismatch either way only costs one duplicate probe.
func searchCandidates(dm *tailcfg.DERPMap, named []probeCandidate, embedded bool) []probeCandidate {
	seenID := set.Set[tailcfg.DERPRegionID]{}
	seenHost := set.Set[string]{}
	for _, c := range named {
		if embedded {
			for _, n := range c.reg.Nodes {
				seenHost.Add(strings.ToLower(n.HostName))
			}
			continue
		}
		seenID.Add(c.reg.RegionID)
	}
	cands := slices.Clone(named)
	for _, id := range slices.Sorted(maps.Keys(dm.Regions)) {
		r := dm.Regions[id]
		if r == nil || seenID.Contains(id) {
			continue
		}
		if len(seenHost) > 0 && slices.ContainsFunc(r.Nodes, func(n *tailcfg.DERPNode) bool {
			return seenHost.Contains(strings.ToLower(n.HostName))
		}) {
			continue
		}
		if cands = append(cands, probeCandidate{r, false}); len(cands) == maxProbeRegions {
			break
		}
	}
	return cands
}

// regionProber sends meow pings to DERP regions to find which of them a
// server is connected to.
type regionProber struct {
	netMon    *netmon.Monitor
	logf      logger.Logf
	priv      key.NodePrivate
	serverPub key.NodePublic
	pkt       []byte
}

// probe meows every region in cands at once and returns those that
// answered, the preferred one first, giving up after timeout.
//
// A server may be registered in more than one region at a time
// (tailcat#7), and a region the address already names is probed alongside
// the rest, so several may answer. probe returns on the first answer,
// except that it waits probeSettle longer for a region the address names,
// whose answer means the address is still good and should not be
// rewritten. Callers must not read a single winner as proof the others
// are dead.
func (p *regionProber) probe(ctx context.Context, cands []probeCandidate, timeout time.Duration) []probeCandidate {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t0 := time.Now()
	answers := make(chan probeCandidate, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i > 0 {
				select {
				case <-time.After(time.Duration(i) * probeStagger):
				case <-ctx.Done():
					return
				}
			}
			if err := p.probeOne(ctx, c.reg); err != nil {
				p.logf("auto-region: region %v (%v): %v", c.reg.RegionID, regionCode(c.reg), err)
				return
			}
			p.logf("auto-region: region %v (%v): server responded in %v", c.reg.RegionID, regionCode(c.reg),
				time.Since(t0).Round(time.Millisecond))
			answers <- c
		}()
	}
	go func() {
		wg.Wait()
		close(answers)
	}()

	var got []probeCandidate
	settle := make(<-chan time.Time) // nil until the first answer
	anyNamed := slices.ContainsFunc(cands, func(c probeCandidate) bool { return c.named })
collect:
	for {
		select {
		case c, ok := <-answers:
			if !ok {
				break collect
			}
			got = append(got, c)
			if c.named || !anyNamed {
				break collect
			}
			// Give a region the address names a moment to answer
			// too, rather than rewriting an address that still works.
			settle = time.After(probeSettle)
		case <-settle:
			break collect
		}
	}
	// Named first, else fastest, which is the order they arrived in.
	slices.SortStableFunc(got, func(a, b probeCandidate) int {
		switch {
		case a.named == b.named:
			return 0
		case a.named:
			return -1
		}
		return 1
	})
	// Every probe must be shut down before the caller brings up its real
	// connection: DERP hands a node key's traffic to whichever of its
	// connections wrote last, so a probe left open to the winning region
	// would fight the connection that replaces it.
	cancel()
	wg.Wait()
	return got
}

// probeOne meows reg until the server acks or ctx expires.
func (p *regionProber) probeOne(ctx context.Context, reg *tailcfg.DERPRegion) error {
	dc := derphttp.NewRegionClient(p.priv, p.logf, p.netMon, func() *tailcfg.DERPRegion { return reg })
	dc.AppName = "tailcat-probe"
	dc.BaseContext = func() context.Context { return ctx }
	defer dc.Close()

	done := make(chan struct{})
	defer close(done)
	// Recv blocks in a socket read, so closing the client is the only way
	// to interrupt it once ctx expires.
	go func() {
		select {
		case <-ctx.Done():
			dc.Close()
		case <-done:
		}
	}()
	go func() {
		t := time.NewTicker(probeMeowInterval)
		defer t.Stop()
		for {
			if err := dc.Send(p.serverPub, p.pkt); err != nil && ctx.Err() == nil {
				p.logf("auto-region: region %v: sending meow: %v", reg.RegionID, err)
			}
			select {
			case <-t.C:
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	for {
		m, err := dc.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return errors.New("no response")
			}
			// derphttp reconnects on the next call; don't spin on a
			// relay that keeps dropping us.
			select {
			case <-time.After(250 * time.Millisecond):
			case <-ctx.Done():
				return errors.New("no response")
			}
			continue
		}
		// Data aliases Recv's buffer, so don't hold on to it.
		if pkt, ok := m.(derp.ReceivedPacket); ok && pkt.Source == p.serverPub && IsMeowedPacket(pkt.Data) {
			return nil
		}
	}
}

func regionCode(r *tailcfg.DERPRegion) string {
	return cmp.Or(r.RegionCode, r.RegionName, fmt.Sprint(r.RegionID))
}

// regionList formats regions for an error or log message.
func regionList(cands []probeCandidate) string {
	var sb strings.Builder
	for i, c := range cands {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%v (%v)", c.reg.RegionID, regionCode(c.reg))
	}
	return sb.String()
}
