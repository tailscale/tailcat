// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/disco"
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

	// probeSettle bounds how long a search waits, after some other
	// region answers, for a region the address already names to answer
	// too. A server reachable in several regions would otherwise have
	// its address rewritten to whichever relay happened to reply first.
	//
	// It is only a bound: the wait ends as soon as every named region
	// has finished probing, which is the answer it is really waiting
	// for. The bound is generous because the alternative to waiting is
	// rewriting an address that is published and still correct, and
	// because a server's first meow after connecting is often dropped,
	// so "slower to answer" and "not there" look alike for a moment.
	probeSettle = 2 * time.Second

	// probeMeowInterval is how often a probe re-sends its meow. It is
	// shorter than meowRetryInterval because a probe has only
	// probeSlotTimeout to get an answer, and the first meow after
	// connecting is often dropped while the server's own DERP connection
	// is still coming up.
	probeMeowInterval = 250 * time.Millisecond

	// probeStagger spaces out the connections a search opens, so a large
	// DERP map doesn't produce one burst of TLS handshakes.
	probeStagger = 100 * time.Millisecond

	// maxProbeConcurrency caps how many regions a search probes at once.
	// Coverage is deliberately not capped: every region in the DERP map
	// is probed eventually, so a server that moved anywhere in a map of
	// any size is still found. What is bounded is how much of the search
	// is in flight, so a stale address costs a fixed number of concurrent
	// TLS handshakes rather than one per region.
	maxProbeConcurrency = 8

	// probeSlotTimeout is how long one region may hold its slot in the
	// pool while other regions are still waiting for one. Without it the
	// first maxProbeConcurrency regions would hold their slots for the
	// whole search and the rest would never be probed at all.
	//
	// A probe whose slot nothing else is waiting for keeps running to the
	// end of the search instead, so a map small enough to probe in one
	// wave behaves exactly as it did before the pool existed.
	probeSlotTimeout = 3 * time.Second

	// probeNotHereGrace is how long a probe keeps meowing after the relay
	// first reports that it holds no connection for the server.
	//
	// A relay answers for the instant it is asked, and it answers fast:
	// the reply lands within a millisecond or two of connecting, well
	// before a server that is really there has answered a meow. A server
	// that has just restarted — the usual reason a search is running at
	// all — is briefly absent from the region it is really in, and the
	// first meow after connecting is often dropped while its own DERP
	// connection comes up, so a live server can take several hundred
	// milliseconds to answer. The grace has to cover that, and it still
	// halves what an empty region costs compared with waiting out
	// probeSlotTimeout.
	//
	// A region written off this way is not written off for good: a
	// search that reaches the end of the map without an answer looks
	// again, and that second look ignores the relay entirely. See
	// DiscoverRegion.
	probeNotHereGrace = 1500 * time.Millisecond

	// probeSearchTimeoutMin and probeSearchTimeoutMax bound the search
	// budget that searchTimeout derives from the size of the map.
	probeSearchTimeoutMin = 15 * time.Second
	probeSearchTimeoutMax = 45 * time.Second
)

var (
	// errNoResponse is a probe that ran out of time with nothing heard.
	errNoResponse = errors.New("no response")

	// errNotHere is a probe the relay itself cut short: it holds no
	// connection for the server's node key. See discoProbePacket.
	errNotHere = errors.New("relay has no record of the server")

	// errYielded is a probe that gave up its slot in the pool to a
	// region that had not been probed yet. It says nothing about
	// whether the server is there.
	errYielded = errors.New("no response yet; yielded to regions not probed yet")
)

// searchTimeout returns how long a search over n regions gets: enough
// for the pool to reach every one of them, since a map larger than
// maxProbeConcurrency is worked through a wave at a time.
func searchTimeout(n int) time.Duration {
	waves := (n + maxProbeConcurrency - 1) / maxProbeConcurrency
	d := time.Duration(waves)*probeSlotTimeout + time.Duration(min(n, maxProbeConcurrency))*probeStagger
	return min(max(d, probeSearchTimeoutMin), probeSearchTimeoutMax)
}

// RegionCache remembers the DERP region a search last found a server in,
// so a client that has already paid for one search doesn't repeat it on
// every later connection. A cached region is probed alongside the one
// the address names rather than in place of it, so a wrong entry costs
// one extra probe and is corrected by the search that follows; entries
// need no expiry for that reason.
//
// Implementations must be safe for concurrent use.
type RegionCache interface {
	// GetRegion returns the region a search last found serverPub in.
	GetRegion(serverPub key.NodePublic) (regionID tailcfg.DERPRegionID, ok bool)

	// PutRegion records that serverPub answered in regionID.
	PutRegion(serverPub key.NodePublic, regionID tailcfg.DERPRegionID) error
}

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
// Every region in the DERP map is searched, however many that is; only
// the number probed at once is bounded (see maxProbeConcurrency).
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
//   - [RegionCache]: remember where the server was found, and look
//     there first next time.
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
	var regions RegionCache
	logf := logger.Discard
	for _, opt := range opts {
		switch v := opt.(type) {
		case DERPMapURL:
			fetchURL = string(v)
		case *tailcfg.DERPMap:
			dm = v
		case DERPMapCache:
			cache = v
		case RegionCache:
			regions = v
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
		pkt:      EncodeMeowPing(clientKey.Public(), DiscoPublicForNode(clientKey).DiscoPublic),
		discoPkt: discoProbePacket(clientKey, ci.ServerDiscoPublic.DiscoPublic),
	}

	// answer turns a winning candidate into the address to use. A region
	// the address already names leaves it alone; anything else rewrites
	// the region and, so the next connection can skip the search,
	// records it.
	answer := func(c probeCandidate) (Addr, error) {
		if c.named {
			return addr, nil
		}
		if regions != nil {
			if err := regions.PutRegion(ci.ServerPublic.NodePublic, c.reg.RegionID); err != nil {
				logf("auto-region: remembering region %v: %v", c.reg.RegionID, err)
			}
		}
		// Multi-region servers are a possibility (tailcat#7), so probe
		// reports every region that answered; today the client connects
		// to one, and the short RegionID form is the only one whose
		// region ID survives a round trip through an [Addr].
		ci.Region = nil
		ci.RegionID = c.reg.RegionID
		return ci.Addr(), nil
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

	// Where a previous search found the server is probed alongside the
	// regions the address names, not instead of them: it goes in
	// unnamed, so if the address's own region answers too, probe's
	// preference for a named region leaves the address alone.
	confirm := namedCands
	if regions != nil {
		if id, ok := regions.GetRegion(ci.ServerPublic.NodePublic); ok {
			if m, err := getMap(); err == nil {
				if r := m.Regions[id]; r != nil && !slices.ContainsFunc(confirm, func(c probeCandidate) bool {
					return c.reg.RegionID == id
				}) {
					confirm = append(slices.Clip(confirm), probeCandidate{r, false})
				}
			}
		}
	}
	if len(confirm) > 0 {
		// Taking the relay's word here can only cost time, never the
		// right answer: the search that follows probes these regions
		// first and returns the address unchanged if one of them
		// answers, so a server still coming up in the region its
		// address names is found a moment later rather than reported
		// as moved.
		if got := p.probe(ctx, confirm, probeConfirmTimeout, true); len(got) > 0 {
			return answer(got[0])
		}
		logf("auto-region: no response in %v; searching the rest of the DERP map", regionList(confirm))
	}

	m, err := getMap()
	if err != nil {
		return "", err
	}
	cands := searchCandidates(m, namedCands, embedded)
	if len(cands) == 0 {
		return "", fmt.Errorf("no DERP regions to search in %v", fetchURL)
	}
	// Two looks, sharing one budget. The first sweeps the whole map fast,
	// taking a relay's word that it has no connection for the server so
	// that a slot frees up for the next region; that is what lets the
	// search cover a map of any size. But a relay answers only for the
	// instant it is asked, and the usual reason a search is running at
	// all is that the server has just restarted — so if the sweep comes
	// back empty, the second look ignores the relay and waits the rest of
	// the budget out for the server to appear.
	deadline := time.Now().Add(searchTimeout(len(cands)))
	got := p.probe(ctx, cands, time.Until(deadline), true)
	if len(got) == 0 && time.Now().Before(deadline) {
		logf("auto-region: no region has the server yet; waiting in %v", regionList(cands))
		got = p.probe(ctx, cands, time.Until(deadline), false)
	}
	if len(got) == 0 {
		// A server ignores meows from a client that isn't on its --allow
		// list in exactly the way an absent server does, so name both.
		return "", fmt.Errorf("no response from the server in any of the %d DERP regions in %v (%v); it may be on a relay not listed there, or this client's key may not be on its --allow list",
			len(cands), fetchURL, regionList(cands))
	}
	// The search re-probes the regions the address names, so a confirm
	// that merely ran slow lands here rather than costing the connection.
	return answer(got[0])
}

// discoProbePacket returns a disco-framed packet addressed to the
// server's disco key, which a probe sends alongside its meow.
//
// Nothing answers it. A live server's magicsock drops disco from a peer
// it doesn't know, which is what keeps this from being a way around the
// server's --allow list — only a meowed counts as the server answering.
// Its job is to look like disco to the *relay*: derpserver replies "peer
// gone, not here" for a disco packet addressed to a node key it holds no
// connection for, and stays silent for anything else, meows included
// (requestPeerGoneWriteLimited). That turns a region the server has left
// into an immediate answer instead of a timeout, which is what lets a
// search cover a large map in one search budget.
func discoProbePacket(clientKey key.NodePrivate, serverDisco key.DiscoPublic) []byte {
	var txid [12]byte
	rand.Read(txid[:])
	payload := (&disco.Ping{TxID: txid, NodeKey: clientKey.Public()}).AppendMarshal(nil)
	priv := discoPrivateForNode(clientKey)
	pkt := make([]byte, 0, 128)
	pkt = append(pkt, disco.Magic...)
	pkt = priv.Public().AppendTo(pkt)
	return append(pkt, priv.Shared(serverDisco).Seal(payload)...)
}

// probeResult is one finished probe: the region, and whether the server
// answered there. Failures are reported too, so the collector can tell
// a region the address names that is still being probed from one that
// has finished and found nothing.
type probeResult struct {
	cand probeCandidate
	ok   bool
}

// probeCandidate is a region to probe, and whether the address being
// resolved already names it.
type probeCandidate struct {
	reg   *tailcfg.DERPRegion
	named bool
}

// searchCandidates returns the regions to probe for a server that did
// not answer in the regions its address named: those regions first, then
// every other region in dm, nearest first.
//
// The named regions are probed again rather than skipped. A confirm stage
// that timed out only because the relay was slow to come up would
// otherwise report a server that never moved as moved, or fail outright
// when nothing else answers.
//
// The rest are ordered by great-circle distance from the named region,
// because a server that re-picks its region by latency and lands
// somewhere new has almost always landed near where it was: the region
// it left was its nearest, so its replacement is usually the next
// nearest. Probing outward finds it in the first wave far more often
// than ascending region ID does, which matters once the map is larger
// than one wave. Regions the map gives no coordinates for keep their ID
// order, after the ones it does.
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
		cands = append(cands, probeCandidate{r, false})
	}
	// An embedded address's regions carry no coordinates (wireRegionOf
	// drops them), so there is nothing to measure from and the ID order
	// stands.
	if lat, lon, ok := originCoords(named); ok {
		rest := cands[len(named):]
		slices.SortStableFunc(rest, func(a, b probeCandidate) int {
			da, aok := distanceKm(lat, lon, a.reg)
			db, bok := distanceKm(lat, lon, b.reg)
			switch {
			case aok && bok:
				return cmp.Compare(da, db)
			case aok:
				return -1
			case bok:
				return 1
			}
			return 0
		})
	}
	return cands
}

// originCoords returns the coordinates to order a search around: those
// of the first named region the map gives any for.
func originCoords(named []probeCandidate) (lat, lon float64, ok bool) {
	for _, c := range named {
		if c.reg.Latitude != 0 || c.reg.Longitude != 0 {
			return c.reg.Latitude, c.reg.Longitude, true
		}
	}
	return 0, 0, false
}

// distanceKm returns the great-circle distance from (lat, lon) to reg,
// and whether reg has coordinates at all. A region with neither is
// reported as unknown rather than as a point off the coast of Africa.
func distanceKm(lat, lon float64, reg *tailcfg.DERPRegion) (float64, bool) {
	if reg.Latitude == 0 && reg.Longitude == 0 {
		return 0, false
	}
	const earthRadiusKm = 6371
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat, dLon := rad(reg.Latitude-lat), rad(reg.Longitude-lon)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(lat))*math.Cos(rad(reg.Latitude))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKm * math.Asin(min(1, math.Sqrt(a))), true
}

// regionProber sends meow pings to DERP regions to find which of them a
// server is connected to.
type regionProber struct {
	netMon    *netmon.Monitor
	logf      logger.Logf
	priv      key.NodePrivate
	serverPub key.NodePublic
	pkt       []byte
	discoPkt  []byte
}

// probe meows the regions in cands, maxProbeConcurrency of them at a
// time, and returns those that answered, the preferred one first, giving
// up after timeout.
//
// A server may be registered in more than one region at a time
// (tailcat#7), and a region the address already names is probed
// alongside the rest, so several may answer. probe returns on the first
// answer from a region the address names, and otherwise holds an answer
// until every named region has finished probing (bounded by
// probeSettle), so that an address whose own region still works is not
// rewritten. Callers must not read a single winner as proof the others
// are dead.
//
// trustNotHere says whether a relay reporting no connection for the
// server ends that region's probe. It makes a sweep of a large map cheap,
// at the cost of writing off a server that has not finished connecting;
// see probeNotHereGrace and DiscoverRegion.
func (p *regionProber) probe(ctx context.Context, cands []probeCandidate, timeout time.Duration, trustNotHere bool) []probeCandidate {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t0 := time.Now()
	results := make(chan probeResult, len(cands))
	queue := make(chan probeCandidate)

	// waiting counts the regions no worker has taken up yet. A probe
	// yields its slot after probeSlotTimeout only while this is non-zero:
	// once every region has been handed out there is no one to make room
	// for, so the probes still running get the rest of the search.
	var waiting atomic.Int64
	waiting.Store(int64(len(cands)))
	go func() {
		defer close(queue)
		for _, c := range cands {
			waiting.Add(-1)
			select {
			case queue <- c:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := range min(len(cands), maxProbeConcurrency) {
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
			for c := range queue {
				err := p.probeSlot(ctx, c.reg, func() bool { return waiting.Load() > 0 }, trustNotHere)
				if err != nil {
					p.logf("auto-region: region %v (%v): %v", c.reg.RegionID, regionCode(c.reg), err)
				} else {
					p.logf("auto-region: region %v (%v): server responded in %v", c.reg.RegionID, regionCode(c.reg),
						time.Since(t0).Round(time.Millisecond))
				}
				results <- probeResult{c, err == nil}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	// namedLeft counts the regions the address names that have not
	// finished probing. An answer from anywhere else is held until that
	// reaches zero — an address whose own region still works must not be
	// rewritten, and only the named probe finishing settles that — or
	// until probeSettle runs out, whichever comes first.
	var namedLeft int
	for _, c := range cands {
		if c.named {
			namedLeft++
		}
	}

	var got []probeCandidate
	var settle <-chan time.Time // nil until something answers
collect:
	for {
		select {
		case r, ok := <-results:
			if !ok {
				break collect
			}
			if r.ok {
				got = append(got, r.cand)
				if r.cand.named {
					break collect
				}
			} else if r.cand.named {
				namedLeft--
			}
			if len(got) == 0 {
				continue
			}
			if namedLeft == 0 {
				break collect
			}
			if settle == nil {
				settle = time.After(probeSettle)
			}
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

// probeSlot probes reg, giving up its slot in the pool after
// probeSlotTimeout if waiting reports that other regions still need one.
func (p *regionProber) probeSlot(ctx context.Context, reg *tailcfg.DERPRegion, waiting func() bool, trustNotHere bool) error {
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var yielded atomic.Bool
	go func() {
		t := time.NewTicker(probeSlotTimeout)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if waiting() {
					yielded.Store(true)
					cancel()
					return
				}
			case <-pctx.Done():
				return
			}
		}
	}()

	err := p.probeOne(pctx, reg, trustNotHere)
	if err != nil && yielded.Load() && ctx.Err() == nil {
		return errYielded
	}
	return err
}

// probeOne meows reg until the server acks, the relay convinces us it
// has no connection for the server, or ctx expires.
func (p *regionProber) probeOne(ctx context.Context, reg *tailcfg.DERPRegion, trustNotHere bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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

	// notHere is closed when the relay first reports no connection for
	// the server, and absent records that the grace after that ran out
	// with the server still silent. Only then is the region written off:
	// see probeNotHereGrace.
	notHere := make(chan struct{})
	var notHereOnce sync.Once
	var absent atomic.Bool
	go func() {
		select {
		case <-notHere:
		case <-ctx.Done():
			return
		}
		select {
		case <-time.After(probeNotHereGrace):
			absent.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()

	go func() {
		t := time.NewTicker(probeMeowInterval)
		defer t.Stop()
		for {
			if err := dc.Send(p.serverPub, p.pkt); err != nil && ctx.Err() == nil {
				p.logf("auto-region: region %v: sending meow: %v", reg.RegionID, err)
			}
			// Only the server answers a meow; only a disco packet gets
			// the relay to say the server isn't there at all. Send both,
			// so an empty region costs a grace period rather than the
			// whole slot. See discoProbePacket.
			if err := dc.Send(p.serverPub, p.discoPkt); err != nil && ctx.Err() == nil {
				p.logf("auto-region: region %v: sending disco probe: %v", reg.RegionID, err)
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
				if absent.Load() {
					return errNotHere
				}
				return errNoResponse
			}
			// derphttp reconnects on the next call; don't spin on a
			// relay that keeps dropping us.
			select {
			case <-time.After(250 * time.Millisecond):
			case <-ctx.Done():
				return errNoResponse
			}
			continue
		}
		switch m := m.(type) {
		case derp.ReceivedPacket:
			// Data aliases Recv's buffer, so don't hold on to it.
			if m.Source == p.serverPub && IsMeowedPacket(m.Data) {
				return nil
			}
		case derp.PeerGoneMessage:
			if trustNotHere && m.Peer == p.serverPub && m.Reason == derp.PeerGoneReasonNotHere {
				notHereOnce.Do(func() { close(notHere) })
			}
		}
	}
}

func regionCode(r *tailcfg.DERPRegion) string {
	return cmp.Or(r.RegionCode, r.RegionName, fmt.Sprint(r.RegionID))
}

// regionList formats regions for an error or log message, abbreviating a
// list too long to print in full.
func regionList(cands []probeCandidate) string {
	const maxShown = 8
	var sb strings.Builder
	for i, c := range cands {
		if i == maxShown {
			fmt.Fprintf(&sb, ", and %d more", len(cands)-maxShown)
			break
		}
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%v (%v)", c.reg.RegionID, regionCode(c.reg))
	}
	return sb.String()
}
