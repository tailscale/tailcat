// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
)

// twoRegionDERPMap runs two independent DERP+STUN servers and returns
// one map holding both, as regions 1 and 2. RunDERPAndSTUN always hands
// back region 1 with a node named "t1", so the second has to be
// renumbered and renamed: netcheck identifies nodes by Name, and two
// nodes sharing one would collide.
func twoRegionDERPMap(t *testing.T) *tailcfg.DERPMap {
	t.Helper()
	a := integration.RunDERPAndSTUN(t, mkLogger(t, "derp1"), "127.0.0.1")
	b := integration.RunDERPAndSTUN(t, mkLogger(t, "derp2"), "127.0.0.1")
	r1, r2 := a.Regions[1], b.Regions[1]
	if r1 == nil || r2 == nil {
		t.Fatal("no region 1 in a test DERP map")
	}
	r1.RegionName = "Test Region 1"
	r2.RegionID, r2.RegionCode, r2.RegionName = 2, "test2", "Test Region 2"
	// RunDERPAndSTUN sets HostName to 127.0.0.1 on both relays. Dialing
	// uses IPv4, which stays loopback; HostName is what embedded-address
	// search uses to skip already-tried relays, so they must differ.
	for _, n := range r1.Nodes {
		n.HostName = "t1.test"
	}
	for _, n := range r2.Nodes {
		n.RegionID, n.Name, n.HostName = 2, "t2", "t2.test"
	}
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: r1, 2: r2}}
}

// staleAddr returns an address for priv's server naming regionID, whether
// or not the server is really there: the situation auto-region exists
// to repair.
func staleAddr(priv key.NodePrivate, regionID tailcfg.DERPRegionID) Addr {
	ci := &ConnInfo{
		ServerPublic:      NodePublic{priv.Public()},
		ServerDiscoPublic: DiscoPublicForNode(priv),
		RegionID:          regionID,
	}
	return ci.Addr()
}

// startServer runs a server in the named region of dm, serving "hello"
// on port 80.
func startServer(t *testing.T, dm *tailcfg.DERPMap, priv key.NodePrivate, regionID tailcfg.DERPRegionID, name string) *Server {
	t.Helper()
	s := &Server{Key: priv, Logf: mkLogger(t, name), Region: dm.Regions[regionID]}
	t.Cleanup(func() { s.Close() })
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port != 80 {
			return nil
		}
		return func(c net.Conn) {
			io.WriteString(c, "hello")
			c.Close()
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server %s Start: %v", name, err)
	}
	return s
}

func TestDiscoverRegion(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	startServer(t, dm, srvPriv, 2, "server")

	old := staleAddr(srvPriv, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got, err := DiscoverRegion(ctx, old, key.NewNode(), dm, mkLogger(t, "discover"))
	if err != nil {
		t.Fatalf("DiscoverRegion: %v", err)
	}
	if got == old {
		t.Fatal("DiscoverRegion returned the stale address unchanged")
	}
	ci, err := ParseAddr(got)
	if err != nil {
		t.Fatalf("parsing corrected address: %v", err)
	}
	if ci.RegionID != 2 {
		t.Errorf("corrected RegionID = %v; want 2", ci.RegionID)
	}
	// Only the region may change; the identity is what makes the
	// corrected address refer to the same server.
	want, _ := ParseAddr(old)
	if ci.ServerPublic != want.ServerPublic {
		t.Errorf("ServerPublic = %v; want %v", ci.ServerPublic, want.ServerPublic)
	}
	if ci.ServerDiscoPublic != want.ServerDiscoPublic {
		t.Errorf("ServerDiscoPublic = %v; want %v", ci.ServerDiscoPublic, want.ServerDiscoPublic)
	}
}

func TestDiscoverRegionUnchanged(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	startServer(t, dm, srvPriv, 1, "server")

	old := staleAddr(srvPriv, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got, err := DiscoverRegion(ctx, old, key.NewNode(), dm, mkLogger(t, "discover"))
	if err != nil {
		t.Fatalf("DiscoverRegion: %v", err)
	}
	if got != old {
		t.Errorf("DiscoverRegion changed a correct address to %v", got)
	}
}

// TestDiscoverRegionAllowlist pins the requirement that discovery probe
// with the key the caller will really connect with. A server started
// with an allowlist ignores a meow from any other key exactly the way an
// absent server does, so probing with a throwaway key would report every
// allowlisted server as missing.
func TestDiscoverRegionAllowlist(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	s := startServer(t, dm, srvPriv, 2, "server")
	clientPriv := key.NewNode()
	s.AddAllowedClient(clientPriv.Public())

	old := staleAddr(srvPriv, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got, err := DiscoverRegion(ctx, old, clientPriv, dm, mkLogger(t, "discover"))
	if err != nil {
		t.Fatalf("DiscoverRegion with the allowed key: %v", err)
	}
	if ci, _ := ParseAddr(got); ci.RegionID != 2 {
		t.Fatalf("corrected RegionID = %v; want 2", ci.RegionID)
	}

	short, cancelShort := context.WithTimeout(ctx, 20*time.Second)
	defer cancelShort()
	if _, err := DiscoverRegion(short, old, key.NewNode(), dm, mkLogger(t, "discover-denied")); err == nil {
		t.Error("DiscoverRegion with a key that isn't allowed = nil error; want failure")
	}

	// The probe registered the client with the server before the real
	// connection did. Because both present the same derived disco key,
	// the entry onMeow kept is the right one and the tunnel still works.
	c := &Client{Server: got, Key: clientPriv, Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	c.DERPMapCache = staticDERPMapCacheForTest(t, dm)
	PingForTest(t, s, c)
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	all, err := io.ReadAll(conn)
	if err != nil || string(all) != "hello" {
		t.Fatalf("read = %q, %v; want %q", all, err, "hello")
	}
}

// TestDiscoPublicMatchesMagicsock guards the invariant that lets a raw
// DERP probe stand in for a real client: the disco key it advertises
// must be the one magicsock will present, or onMeow would record a key
// the real client can no longer correct.
func TestDiscoPublicMatchesMagicsock(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	s := startServer(t, dm, srvPriv, 1, "server")

	clientPriv := key.NewNode()
	c := &Client{Server: s.TailcatAddr(), Key: clientPriv, Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	WaitForDERPForTest(t, s, c)

	got := c.lb.sys.MagicSock.Get().DiscoPublicKey()
	if want := DiscoPublicForNode(clientPriv).DiscoPublic; got != want {
		t.Errorf("magicsock disco key = %v; want DiscoPublicForNode = %v", got, want)
	}
}

func TestDiscoverRegionEmbedded(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	startServer(t, dm, srvPriv, 2, "server")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// A "--full-address" address for region 1: self-contained, and just as
	// stale as a short one once the server moves.
	old, err := staleAddr(srvPriv, 1).Resolve(ctx, dm)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ci, _ := ParseAddr(old); len(ci.Region) == 0 {
		t.Fatal("Resolve didn't embed the region")
	}
	got, err := DiscoverRegion(ctx, old, key.NewNode(), dm, mkLogger(t, "discover"))
	if err != nil {
		t.Fatalf("DiscoverRegion: %v", err)
	}
	ci, err := ParseAddr(got)
	if err != nil {
		t.Fatalf("parsing corrected address: %v", err)
	}
	if ci.RegionID != 2 {
		t.Errorf("corrected RegionID = %v; want 2", ci.RegionID)
	}
	if len(ci.Region) != 0 {
		t.Errorf("corrected address embeds %d regions; want the short form", len(ci.Region))
	}
}

func TestDiscoverRegionNotFound(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode() // no server ever started

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := DiscoverRegion(ctx, staleAddr(srvPriv, 1), key.NewNode(), dm, mkLogger(t, "discover"))
	if err == nil {
		t.Fatal("DiscoverRegion found a server that doesn't exist")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DiscoverRegion ran out the caller's context rather than its own budget: %v", err)
	}
	// A client missing from an allowlist sees the same silence, so the
	// error has to raise that possibility too.
	if !strings.Contains(err.Error(), "--allow") {
		t.Errorf("error %q doesn't mention the allowlist possibility", err)
	}
}

// TestDiscoverRegionMultiHomed covers a server reachable in more than
// one region, which tailcat#7 contemplates. Every region it is in
// answers a probe, so discovery must pick one and move on rather than
// treat the extra answers as an error or wait for stragglers.
func TestDiscoverRegionMultiHomed(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	startServer(t, dm, srvPriv, 1, "server1")
	startServer(t, dm, srvPriv, 2, "server2")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Naming a region the server really is in: nothing moved.
	old := staleAddr(srvPriv, 1)
	got, err := DiscoverRegion(ctx, old, key.NewNode(), dm, mkLogger(t, "discover"))
	if err != nil {
		t.Fatalf("DiscoverRegion: %v", err)
	}
	if got != old {
		t.Errorf("DiscoverRegion changed an address naming a live region to %v", got)
	}

	// Naming a region it isn't in: either of the others is a valid answer.
	got, err = DiscoverRegion(ctx, staleAddr(srvPriv, 3), key.NewNode(), dm, mkLogger(t, "discover"))
	if err != nil {
		t.Fatalf("DiscoverRegion from an unknown region: %v", err)
	}
	if ci, _ := ParseAddr(got); ci.RegionID != 1 && ci.RegionID != 2 {
		t.Errorf("corrected RegionID = %v; want 1 or 2", ci.RegionID)
	}
}

func TestClientAutoRegion(t *testing.T) {
	t.Parallel()
	dm := twoRegionDERPMap(t)
	srvPriv := key.NewNode()
	s := startServer(t, dm, srvPriv, 2, "server")

	var gotAddr Addr
	var gotRegion tailcfg.DERPRegionID
	var calls int
	c := &Client{
		Server:       staleAddr(srvPriv, 1),
		Logf:         mkLogger(t, "client"),
		AutoRegion:   true,
		DERPMapCache: staticDERPMapCacheForTest(t, dm),
		OnRegionDiscovered: func(b Addr, r *tailcfg.DERPRegion) {
			calls++
			gotAddr, gotRegion = b, r.RegionID
		},
	}
	t.Cleanup(func() { c.Close() })

	pub := c.PublicKey()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if calls != 1 {
		t.Errorf("OnRegionDiscovered called %d times; want 1", calls)
	}
	if gotRegion != 2 {
		t.Errorf("discovered region = %v; want 2", gotRegion)
	}
	if got, ok := c.DiscoveredServer(); !ok || got != gotAddr {
		t.Errorf("DiscoveredServer = %v, %v; want %v, true", got, ok, gotAddr)
	}
	// The identity must survive discovery: it's what the server
	// allowlists, and what its address is derived from.
	if got := c.PublicKey(); got != pub {
		t.Errorf("PublicKey changed across discovery: %v, was %v", got, pub)
	}
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	all, err := io.ReadAll(conn)
	if err != nil || string(all) != "hello" {
		t.Fatalf("read = %q, %v; want %q", all, err, "hello")
	}
	_ = s
}

func TestSearchCandidates(t *testing.T) {
	mk := func(id tailcfg.DERPRegionID, host string) *tailcfg.DERPRegion {
		return &tailcfg.DERPRegion{
			RegionID: id,
			Nodes:    []*tailcfg.DERPNode{{HostName: host}},
		}
	}
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: mk(1, "a.example.com"),
		2: mk(2, "b.example.com"),
		3: mk(3, "c.example.com"),
	}}
	// desc renders each candidate as its region ID, with a "*" for the
	// ones the address already names.
	desc := func(cands []probeCandidate) string {
		var sb strings.Builder
		for i, c := range cands {
			if i > 0 {
				sb.WriteString(" ")
			}
			fmt.Fprintf(&sb, "%v", c.reg.RegionID)
			if c.named {
				sb.WriteString("*")
			}
		}
		return sb.String()
	}
	named := func(r *tailcfg.DERPRegion) []probeCandidate {
		return []probeCandidate{{r, true}}
	}

	// The named region is probed again, first, so that a confirm stage
	// that only ran slow doesn't get read as the server having moved.
	if got, want := desc(searchCandidates(dm, named(dm.Regions[2]), false)), "2* 1 3"; got != want {
		t.Errorf("candidates for an address naming region 2 = %q; want %q", got, want)
	}

	// In-process test relays share 127.0.0.1 as HostName. Map-derived
	// regions are matched by ID, so both must still be probed.
	sameHost := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: mk(1, "127.0.0.1"),
		2: mk(2, "127.0.0.1"),
	}}
	if got, want := desc(searchCandidates(sameHost, named(sameHost.Regions[1]), false)), "1* 2"; got != want {
		t.Errorf("candidates when map regions share a hostname = %q; want %q", got, want)
	}

	// An embedded address's region IDs are synthesized as 1..N, so the map
	// entry for the relay it names is recognized by hostname and not
	// probed twice. The map's own region 1 is a different relay and is.
	if got, want := desc(searchCandidates(dm, named(mk(1, "C.EXAMPLE.COM")), true)), "1* 1 2"; got != want {
		t.Errorf("candidates for an embedded address = %q; want %q", got, want)
	}
}

// staticDERPMapCacheForTest makes dm the answer to any DERP map fetch,
// so a test client resolves regions without a map server.
func staticDERPMapCacheForTest(t *testing.T, dm *tailcfg.DERPMap) DERPMapCache {
	t.Helper()
	j, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	return staticDERPMapCache{j}
}

type staticDERPMapCache struct{ j []byte }

func (c staticDERPMapCache) Get(string) (data []byte, etag string, storedAt time.Time, ok bool) {
	return c.j, "", time.Now(), true
}
func (staticDERPMapCache) Put(string, []byte, string) error { return nil }
