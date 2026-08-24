// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailcat implements a control-plane-free network pipe built on
// Tailscale's data plane which provides encryption (WireGuard) and NAT traversal.
// This is the library behind the "tailcat" CLI command (cmd/tailcat).
//
// A [Server] listens for incoming clients via a DERP relay. Clients discover
// the server through a compact [ConnBlob] (connection blob) that encodes the
// server's public key and DERP region. DERP is used only for the initial
// bootstrap; once both sides learn each other's endpoints, Tailscale's
// magicsock layer upgrades to a direct peer-to-peer UDP path whenever possible,
// just like the normal Tailscale data plane. DERP remains available as a
// fallback relay if a direct path cannot be established.
//
// Once connected, the two sides exchange arbitrary TCP traffic over the
// WireGuard tunnel with no Tailscale account or coordination server required.
// Optionally, the server can run an auth-free SSH server on port 22, providing
// remote shell access over the tunnel.
//
// The name "tailcat" is a nod to the classic "netcat" tool, but with
// Tailscale's WireGuard encryption + NAT traversal.
//
// Using Tailscale's DERP servers is not required; you can run your own DERP
// server and provide its region information in the ConnBlob.
package tailcat

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	go4mem "go4.org/mem"
	"go4.org/netipx"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// Verbose controls whether extra diagnostic logging is emitted during
// DERP region auto-detection (netcheck).
var Verbose = false

// DefaultDERPMapURL is the URL of the JSON-encoded [tailcfg.DERPMap]
// that [ConnInfo.Expand] fetches when no alternate DERP map source is
// specified via options.
const DefaultDERPMapURL = "https://tailcat.dev/derpmap.json"

// DERPMapURL is an option for [ConnInfo.Expand] specifying an
// alternate URL to fetch the DERP map from instead of
// [DefaultDERPMapURL].
type DERPMapURL string

// ExpandForServer is an option for [ConnInfo.Expand] that marks the
// DERP map fetch as being on behalf of a tailcat server (which will
// listen on the chosen region) rather than a client. It is sent as a
// hint header to the DERP map server.
var ExpandForServer expandForServer

type expandForServer struct{}

// ConnBlob is a compact, URL-safe string that a server gives to clients so
// they can connect. It is the "tc"-prefixed base64url encoding of CBOR-encoded
// [ConnInfo]. A typical ConnBlob looks like "tcomFwWC…".
type ConnBlob string

// ConnInfo describes how to reach a server: its public key and which DERP
// relay region to use. It is serialized into a [ConnBlob] for exchange,
// via the wire types in wire.go.
type ConnInfo struct {
	ServerPublic NodePublic // a key.NodePublic

	// Region, if non-empty, lists the regions of a DERPMap.
	// Either Region or RegionID must be set. If Region is set
	// the client can avoid doing a lookup to discover the DERP map
	// but the ConnBlob is longer.
	//
	// As of 2023-09-22, a maximum of 1 region may be provided.
	// In the future, a server might advertise its presence in
	// multiple DERP regions and clients could try them all.
	Region []*tailcfg.DERPRegion `json:",omitempty"`

	// RegionID lists the number of one of Tailscale's provided
	// DERP servers. If set, Region may be omitted and the ConnBlob
	// is shorter, at the cost of the client needing to fetch
	// the derpmap from tailscale.com once at startup.
	// If -1 (for use when saving a keypair to disk for reuse later), a region
	// is selected automatically at startup based on latency.
	RegionID int `json:",omitempty"`
}

// NodePublic is a wrapper around key.NodePublic just so we can have a slightly
// smaller CBOR representation without the "np" prefix.
type NodePublic struct {
	key.NodePublic
}

// MarshalBinary implements encoding.BinaryMarshaler for CBOR serialization,
// encoding the raw 32-byte key without the "nodekey:" text prefix.
func (p NodePublic) MarshalBinary() ([]byte, error) {
	return p.NodePublic.AppendTo(nil), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for CBOR deserialization.
func (p *NodePublic) UnmarshalBinary(x []byte) error {
	p.NodePublic = key.NodePublicFromRaw32(go4mem.B(x))
	return nil
}

// Equal reports whether a and b represent the same public key.
func (a NodePublic) Equal(b NodePublic) bool {
	return a == b
}

// PrivateKey is a node identity: a private key paired with the connection
// info needed to reach this node. The DERP region in Public must be
// populated by the caller before the key is usable.
type PrivateKey struct {
	Private key.NodePrivate
	Public  ConnInfo
}

// NewPrivateKey returns a new PrivateKey, but without
// the DERP region populated. It's up to the caller to
// populate that.
func NewPrivateKey() *PrivateKey {
	ret := &PrivateKey{
		Private: key.NewNode(),
	}
	ret.Public.ServerPublic = NodePublic{ret.Private.Public()}
	return ret
}

// locoBackend is like tailscaled's LocalBackend, but crazier.
// It serves a similar purpose (to be the hub of the world)
// but there's no controlclient involved, because there's
// no control plane.
type locoBackend struct {
	sys        tsd.System
	priv       key.NodePrivate
	pub        key.NodePublic
	addr       netip.Addr
	addrPrefix netip.Prefix
	ns         *netstack.Impl
	dm         *tailcfg.DERPMap
	logf       logger.Logf
	serverPub  key.NodePublic // non-zero if we're a client (server's public key)
	isServer   bool

	// discoPublic returns the node's disco public key, memoized to
	// avoid redoing the curve25519 derivation for every client that
	// joins.
	discoPublic func() key.DiscoPublic

	// onDERPRecv is called for non-disco DERP packets before the
	// peer map lookup. Set before createEngine.
	onDERPRecv func(regionID int, src key.NodePublic, pkt []byte) bool

	mu             sync.Mutex
	clients        map[key.NodePublic]*tailcfg.Node // for the server
	nm             *netmap.NetworkMap
	allowedClients map[key.NodePublic]bool // or nil map for all
}

func (b *locoBackend) derpRegionID() int {
	if b.dm == nil {
		panic("no derp map")
	}
	for _, r := range b.dm.Regions {
		return r.RegionID
	}
	panic("no derp regions in derp map")
}

func (b *locoBackend) Close() error {
	if e, ok := b.sys.Engine.GetOK(); ok {
		e.Close()
	}
	if m, ok := b.sys.NetMon.GetOK(); ok {
		m.Close()
	}
	return nil
}

// Server listens for clients over a WireGuard tunnel relayed through DERP.
// Incoming TCP connections are dispatched via [Server.OnTCP] (for connections
// addressed to the server itself) and [Server.OnTCPForward] (for connections
// the server relays to other addresses, acting as an exit node).
//
// Create one with [NewServer], configure the OnTCP/OnTCPForward callbacks,
// then call [Server.Start].
type Server struct {
	lb *locoBackend

	// AllowProxy, if non-nil, reports whether
	// a TCP or UDP proxy is allowed for that target.
	AllowProxy func(netip.AddrPort) bool

	// OnTCP, if non-nil, specifies a func that returns a handler to handle
	// incoming connections to the provided port. If nil or if it returns nil,
	// then a RST is sent.
	//
	// This only applies to connections directly to the server node and not
	// when being a subnet router. See OnTCPForward for relayed connections.
	//
	// It must be set before calling Start.
	OnTCP func(port uint16) (handler func(net.Conn))

	// OnTCPForward, if non-nil, specifies a func that returns a handler to handle
	// incoming connections to the provided IP:port. If nil or if it returns nil,
	// then a RST is sent.
	//
	// This only applies to connections relayed through the server and not to the server
	// itself. See OnTCP for direct connections to the server.
	//
	// It must be set before calling Start. Setting it also widens the
	// packet filter installed at Start to admit traffic to any
	// destination, not just the server's own address.
	OnTCPForward func(netip.AddrPort) (handler func(net.Conn))

	// OnClientConnect, if non-nil, is called from its own goroutine
	// when a new client completes the meow handshake and is added as
	// a WireGuard peer. It is called at most once per client key.
	//
	// It must be set before calling Start.
	OnClientConnect func(key.NodePublic)

	// ServedTCPPorts, if non-nil, restricts which TCP ports on the
	// server's own address the packet filter admits new inbound
	// connections to. If nil, connections to all ports reach OnTCP,
	// which remains the per-port gate either way. Callers that know
	// their served ports statically (like the tailcat CLI) can set
	// this for defense in depth.
	//
	// Unlike OnTCP's nil-handler response, packets dropped by the
	// filter get no RST; a client dialing a filtered port times out.
	//
	// It must be set before calling Start.
	ServedTCPPorts []filter.PortRange
}

// NewServer creates a new server with the given node private key, using the
// provided DERP region as its relay. Exactly one DERPRegion must be provided.
// After creating the server, set [Server.OnTCP] and/or [Server.OnTCPForward],
// then call [Server.Start].
func NewServer(priv key.NodePrivate, logf logger.Logf, regs ...*tailcfg.DERPRegion) (*Server, error) {
	lb := newLocoBackend(priv)
	srv := &Server{
		lb: lb,
	}

	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	if len(regs) != 1 {
		return nil, fmt.Errorf("exactly 1 DERPRegion required for now, not %v", len(regs))
	}
	for _, r := range regs {
		if r.RegionID == 0 {
			return nil, fmt.Errorf("missing RegionID in %v", logger.AsJSON(r))
		}
		mak.Set(&lb.dm.Regions, r.RegionID, r)
	}

	sys := &lb.sys
	bus := eventbus.New()
	sys.Set(bus)
	sys.Set(health.NewTracker(bus))

	netMon, err := netmon.New(bus, func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return nil, fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)

	var store ipn.StateStore = new(mem.Store)
	sys.Set(store)

	lb.isServer = true
	lb.onDERPRecv = func(regionID int, src key.NodePublic, pkt []byte) bool {
		if !IsMeowPacket(pkt) {
			return false
		}
		if IsMeowedPacket(pkt) {
			return true // server ignores meowed
		}
		if _, discoPub, ok := ParseMeowPing(pkt); ok {
			mc := lb.sys.MagicSock.Get()
			go func() {
				// Only reply once the client is fully added as a peer:
				// "meowed" is the ack that tells the client it can
				// start dialing. Disallowed clients get no reply.
				allowed, isNew := lb.onMeow(src, discoPub)
				if !allowed {
					return
				}
				mc.SendDERPPacketTo(src, regionID, EncodeMeowed())
				if isNew && srv.OnClientConnect != nil {
					srv.OnClientConnect(src)
				}
			}()
			return true
		}
		return false
	}

	if err := createEngine(logf, lb); err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	ns, err := newNetstack(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		if dst.Addr() == srv.Addr() {
			if srv.OnTCP == nil {
				return nil, true // send RST
			}
			return srv.OnTCP(dst.Port()), true
		}
		if srv.OnTCPForward == nil {
			return nil, true // send RST
		}
		if nat64Prefix.Contains(dst.Addr()) {
			var a4 [4]byte
			d6 := dst.Addr().As16()
			copy(a4[:], d6[12:16])
			dst = netip.AddrPortFrom(netip.AddrFrom4(a4), dst.Port())
		}
		return srv.OnTCPForward(dst), true
	}
	lb.ns = ns
	sys.Set(ns)

	e := sys.Engine.Get()
	// Reject all inbound traffic until Start installs the real filter,
	// built from what the server is configured to serve.
	e.SetFilter(filter.NewAllowNone(logf, nil))
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := lb.peerByIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}
	dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		panic("unreachable from tailcat") // but required by Dialer currently
	}

	sys.Tun.Get().Start()

	return srv, nil
}

var allTCPPorts = filter.PortRange{First: 0, Last: 65535}

// buildFilter returns the packet filter enforcing what the server is
// configured to serve: new inbound TCP connections are admitted only
// to the server's own address (limited to ServedTCPPorts if set),
// plus to any destination when OnTCPForward is set (exit node mode).
// Everything else from the tunnel is dropped before reaching
// netstack; the OnTCP/OnTCPForward callbacks remain the
// per-connection gates behind it.
func (s *Server) buildFilter() *filter.Filter {
	lb := s.lb

	selfPorts := []filter.PortRange{allTCPPorts}
	if s.ServedTCPPorts != nil {
		selfPorts = s.ServedTCPPorts
	}
	var selfDsts []filter.NetPortRange
	for _, pr := range selfPorts {
		selfDsts = append(selfDsts, filter.NetPortRange{Net: lb.addrPrefix, Ports: pr})
	}
	matches := []filter.Match{{
		IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP}),
		Srcs:    []netip.Prefix{allIPv6},
		Dsts:    selfDsts,
	}}

	var localNets netipx.IPSetBuilder
	localNets.AddPrefix(lb.addrPrefix)
	if s.OnTCPForward != nil {
		localNets.AddPrefix(allIPv6)
		matches = append(matches, filter.Match{
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP}),
			Srcs:    []netip.Prefix{allIPv6},
			Dsts:    []filter.NetPortRange{{Net: allIPv6, Ports: allTCPPorts}},
		})
	}
	local, _ := localNets.IPSet()
	return filter.New(matches, nil, local, nil, nil, lb.logf)
}

// Addr returns the server's IPv6 address derived from its public key.
func (s *Server) Addr() netip.Addr { return s.lb.addr }

// Start connects to the DERP relay and begins accepting clients.
func (s *Server) Start() error {
	s.lb.sys.Engine.Get().SetFilter(s.buildFilter())
	return s.lb.Start()
}

// WaitDERPConnected blocks until the server has an established
// connection to its DERP relay region, or ctx is done. Start
// initiates that connection but does not wait for it; a meow from a
// client that arrives at the relay before the server is connected is
// lost, so callers that hand out the ConnBlob immediately after Start
// should wait first.
func (s *Server) WaitDERPConnected(ctx context.Context) error {
	regionID := s.lb.derpRegionID()
	ht := s.lb.sys.HealthTracker.Get()
	for ht.GetDERPRegionReceivedTime(regionID).IsZero() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return nil
}

// Close shuts down the server, closing the WireGuard engine and DERP connections.
func (s *Server) Close() error { return s.lb.Close() }

// DrainTCP waits until every TCP connection in the server's netstack
// has fully closed, meaning the peer has acknowledged all sent data
// and the final FIN. It returns nil once drained, or ctx's error.
//
// The whole TCP stack runs inside this process, so exiting right
// after a [net.Conn] Close can lose the FIN before it is ever
// transmitted, leaving the peer waiting for an EOF that never comes.
// A process that closes a connection and then exits should first
// call DrainTCP with a timeout bounding ctx, in case the peer is
// gone and the FIN is never acknowledged.
//
// It is meant for the passive closer (the side that closes second),
// which goes straight to CLOSED once its FIN is acked. A connection
// this side closed first instead parks in TIME-WAIT and would block
// DrainTCP until the TIME-WAIT timer fires.
func (s *Server) DrainTCP(ctx context.Context) error {
	// Wait blocks until the endpoint is fully closed (EventHUp).
	// Non-TCP endpoints return immediately. A waiter goroutine may
	// outlive an early ctx cancellation; it exits with the process
	// or when its endpoint eventually closes.
	for _, ep := range tcpipStackOf(s.lb.ns).RegisteredEndpoints() {
		done := make(chan struct{})
		go func() {
			ep.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// tcpipStackOf returns ns's unexported gVisor *stack.Stack.
//
// TODO(bradfitz): add an exported accessor to wgengine/netstack.Impl
// upstream and delete this reflect+unsafe cheat.
func tcpipStackOf(ns *netstack.Impl) *stack.Stack {
	v := reflect.ValueOf(ns).Elem().FieldByName("ipstack")
	if !v.IsValid() {
		panic("netstack.Impl has no ipstack field; tailscale.com dep changed?")
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(*stack.Stack)
}

// AddAllowedClient adds k as an allowed client.
//
// Before this method is called once, all clients are allowed.
func (s *Server) AddAllowedClient(k key.NodePublic) {
	s.lb.mu.Lock()
	defer s.lb.mu.Unlock()
	mak.Set(&s.lb.allowedClients, k, true)
}

// ConnBlobForTest returns a [ConnBlob] that clients can use to connect to
// this server. It includes the full DERP region so clients don't need to
// fetch the DERP map from the network.
func (s *Server) ConnBlobForTest() ConnBlob {
	return s.lb.ConnBlobForTest()
}

func newLocoBackend(priv key.NodePrivate) *locoBackend {
	pub := priv.Public()
	addr := tcAddrForKey(pub)
	addrPrefix := netip.PrefixFrom(addr, addr.BitLen())
	lb := &locoBackend{
		logf:       log.Printf,
		priv:       priv,
		pub:        pub,
		addr:       addr,
		addrPrefix: addrPrefix,
	}
	lb.discoPublic = sync.OnceValue(func() key.DiscoPublic {
		return nodePrivateAsDiscoPrivate(lb.priv).Public()
	})
	return lb
}

var debugConnBlob = envknob.Bool("TS_DEBUG_CONNBLOB")

func (lb *locoBackend) ConnBlobForTest() ConnBlob {
	if lb.dm == nil {
		panic("no DERPMap set")
	}
	var ci ConnInfo
	ci.ServerPublic = NodePublic{lb.pub}
	for _, r := range lb.dm.Regions {
		ci.Region = append(ci.Region, r)
	}
	if len(lb.dm.Regions) == 0 {
		panic("no regions in derpmap")
	}
	if debugConnBlob {
		log.Printf("ConnBlob: %v", logger.AsJSON(ci))
	}
	return ci.ConnBlob()
}

// ConnBlob serializes the ConnInfo into a compact [ConnBlob] string.
// It is encoded via the wire types (see wire.go), which drop the
// DERP region fields tailcat doesn't use. Some other fields
// (RegionID, RegionCode, implicit HostNames) are zeroed before
// encoding to reduce size; [ParseConnBlob] restores them.
func (ci *ConnInfo) ConnBlob() ConnBlob {
	w := &wireConnInfo{
		ServerPublic: ci.ServerPublic,
		RegionID:     ci.RegionID,
	}
	for _, r := range ci.Region {
		wr := wireRegionOf(r)

		// Remove some fields before encoding to save space. The same
		// transforms are undone on the way back.
		wr.RegionID = 0
		wr.RegionCode = ""
		for _, n := range wr.Nodes {
			n.RegionID = 0
			implicitHost := "derp" + n.Name + ".tailscale.com"
			if n.HostName == implicitHost {
				n.HostName = ""
			}
		}
		w.Region = append(w.Region, wr)
	}

	x, err := cbor.Marshal(w)
	if err != nil {
		panic(err)
	}
	if debugConnBlob {
		log.Printf("ConnBlob: %q", x)
		log.Printf("ConnBlob: %x", x)
	}
	return "tc" + ConnBlob(base64.RawURLEncoding.EncodeToString(x))
}

// Resolve returns a self-contained equivalent of b with the DERP
// relay's details embedded, so that later use of the blob requires
// no network access to fetch the DERP map. It is to a ConnBlob
// roughly what a DNS lookup is to a hostname: the resolved form is
// longer, works offline, and pins the relay details as they were at
// resolution time. If b already embeds its relay details, it is
// returned unchanged. The opts are as documented on [ConnInfo.Expand].
func (b ConnBlob) Resolve(ctx context.Context, opts ...any) (ConnBlob, error) {
	ci, err := ParseConnBlob(b)
	if err != nil {
		return "", err
	}
	if len(ci.Region) > 0 {
		return b, nil
	}
	if err := ci.Expand(ctx, opts...); err != nil {
		return "", err
	}
	// Keep the blob short: two relay nodes suffice, and their IPv6
	// addresses can be re-derived from DNS.
	for _, r := range ci.Region {
		r.Nodes = r.Nodes[:min(2, len(r.Nodes))]
		for _, n := range r.Nodes {
			n.IPv6 = ""
		}
	}
	ci.RegionID = 0
	return ci.ConnBlob(), nil
}

// ParseConnBlob decodes a [ConnBlob] back into a [ConnInfo], restoring
// fields that were stripped during encoding (RegionID, RegionCode, implicit
// Tailscale DERP hostnames).
func ParseConnBlob(cb ConnBlob) (ConnInfo, error) {
	var zero ConnInfo
	rest, ok := strings.CutPrefix(string(cb), "tc")
	if !ok {
		return zero, errors.New("server address doesn't start with \"tc\"")
	}
	x, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return zero, fmt.Errorf("base64 decode: %w", err)
	}
	var w wireConnInfo
	if err := cbor.Unmarshal(x, &w); err != nil {
		return zero, fmt.Errorf("CBOR unmarshal: %v", err)
	}
	ci := ConnInfo{
		ServerPublic: w.ServerPublic,
		RegionID:     w.RegionID,
	}
	for _, wr := range w.Region {
		ci.Region = append(ci.Region, wr.derpRegion())
	}
	for ri, r := range ci.Region {
		if r.RegionID == 0 {
			r.RegionID = ri + 1
		}
		if r.RegionCode == "" {
			r.RegionCode = fmt.Sprint(r.RegionID)
		}
		for _, n := range r.Nodes {
			if n.HostName == "" && n.Name != "" && unicode.IsNumber(rune(n.Name[0])) {
				n.HostName = "derp" + n.Name + ".tailscale.com"
			}
			if n.RegionID == 0 {
				n.RegionID = r.RegionID
			}
		}
	}
	return ci, nil
}

// Expand populates ci.Region from a DERP map if only ci.RegionID was set.
// If ci.Region is already populated, Expand is a no-op. When RegionID is -1,
// the best region is selected automatically via netcheck latency probes.
//
// The opts may contain any of the following types:
//   - [DERPMapURL]: fetch the DERP map from an alternate URL instead
//     of [DefaultDERPMapURL].
//   - [*tailcfg.DERPMap]: expand from the provided DERP map instead
//     of fetching one over the network.
//   - [ExpandForServer]: mark the DERP map fetch as being on behalf
//     of a tailcat server rather than a client.
func (ci *ConnInfo) Expand(ctx context.Context, opts ...any) error {
	fetchURL := DefaultDERPMapURL
	mode := "client"
	var dm *tailcfg.DERPMap
	for _, opt := range opts {
		switch v := opt.(type) {
		case DERPMapURL:
			fetchURL = string(v)
		case *tailcfg.DERPMap:
			dm = v
		case expandForServer:
			mode = "server"
		default:
			return fmt.Errorf("unknown Expand option type %T", opt)
		}
	}
	for _, r := range ci.Region {
		if r.RegionID == 0 {
			r.RegionID = 1
		}
		for _, n := range r.Nodes {
			if n.RegionID == 0 {
				n.RegionID = r.RegionID
			}
		}
	}

	if len(ci.Region) > 0 || ci.RegionID == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dmSrc := "provided DERP map"
	if dm == nil {
		dmSrc = fetchURL
		req, err := http.NewRequestWithContext(ctx, "GET", fetchURL, nil)
		if err != nil {
			return fmt.Errorf("fetching DERPMap for region %v: %w", ci.RegionID, err)
		}
		req.Header.Set("Tailcat-Mode", mode)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("fetching DERPMap for region %v: %w", ci.RegionID, err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("fetching DERPMap for region %v: %v", ci.RegionID, res.Status)
		}
		dm = new(tailcfg.DERPMap)
		if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
			return fmt.Errorf("fetching DERPMap for region %v, invalid JSON from %v: %w", ci.RegionID, fetchURL, err)
		}
	}
	if ci.RegionID == -1 {
		// Shuffle each DERP region's nodes.
		for _, r := range dm.Regions {
			rand.Shuffle(len(r.Nodes), reflect.Swapper(r.Nodes))
		}

		regionID, err := PickBestRegion(ctx, dm)
		if err != nil {
			return err
		}
		if regionID != 0 {
			ci.RegionID = 0
			ci.Region = []*tailcfg.DERPRegion{dm.Regions[regionID]}
			return nil
		}

		// Netcheck failed? Just pick a random region from the map,
		// ignoring what's close to the user. Assume the server
		// filtered the map based on our IP when the Tailcat-Mode
		// header was "server".
		regIDs := slices.Sorted(maps.Keys(dm.Regions))
		if len(regIDs) == 0 {
			return errors.New("failed to auto-detect any regions")
		}
		regID := regIDs[rand.Intn(len(regIDs))]
		ci.RegionID = 0
		ci.Region = append(ci.Region, dm.Regions[regID])
		return nil
	}
	r, ok := dm.Regions[ci.RegionID]
	if !ok {
		return fmt.Errorf("connection string said only DERP RegionID %v but no such region in %v", ci.RegionID, dmSrc)
	}
	ci.Region = append(ci.Region, r)
	return nil
}

var allIPv6 = netip.MustParsePrefix("::/0")

// peerAllowedIPs returns the prefixes that the peer with public key k
// is allowed to originate traffic from. It is the engine's per-peer
// WireGuard config source (see [wgengine.Engine.SetPeerConfigFunc]).
func (b *locoBackend) peerAllowedIPs(k key.NodePublic) (allowedIPs []netip.Prefix, ok bool) {
	if !b.serverPub.IsZero() {
		// We're the client; the server is our only peer and may send
		// from any address (it can act as an exit node).
		if k == b.serverPub {
			return []netip.Prefix{pfxOf(tcAddrForKey(k)), allIPv6}, true
		}
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.clients[k]
	if !ok {
		return nil, false
	}
	return n.AllowedIPs, true
}

// peerByIP returns the public key of the peer that outbound packets
// addressed to dst should be sent to (see
// [wgengine.Engine.SetPeerByIPPacketFunc]).
func (b *locoBackend) peerByIP(dst netip.Addr) (_ key.NodePublic, ok bool) {
	if !b.serverPub.IsZero() {
		// We're the client; all traffic goes to the server.
		return b.serverPub, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k := range b.clients {
		if tcAddrForKey(k) == dst {
			return k, true
		}
	}
	return key.NodePublic{}, false
}

func (lb *locoBackend) Start() error {
	if err := lb.ns.Start(nil /* no LocalBackend */); err != nil {
		return fmt.Errorf("failed to start netstack: %w", err)
	}

	e := lb.sys.Engine.Get()
	mc := lb.sys.MagicSock.Get()
	lb.logf("disco pub key: %v", mc.DiscoPublicKey())

	mc.SetPrivateKey(lb.priv)
	mc.SetDERPMap(lb.dm)

	derpRegion := lb.derpRegionID()

	nm := &netmap.NetworkMap{
		NodeKey: lb.pub,
	}
	if lb.serverPub.IsZero() {
		// We're the server. (hence the serverPub is zero)
		nm.SelfNode = (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.tailcat.",
			User:       100,
			Key:        lb.pub,
			DiscoKey:   mc.DiscoPublicKey(),
			Addresses:  []netip.Prefix{lb.addrPrefix},
			AllowedIPs: []netip.Prefix{lb.addrPrefix, allIPv6},
			HomeDERP:   derpRegion,
		}).View()
	} else {
		// We're the client.
		serverAddr := tcAddrForKey(lb.serverPub)
		serverAddrPrefix := netip.PrefixFrom(serverAddr, serverAddr.BitLen())

		nm.SelfNode = (&tailcfg.Node{
			ID:        2,
			StableID:  "2",
			Name:      "client.tailcat.",
			User:      100,
			Key:       lb.pub,
			DiscoKey:  mc.DiscoPublicKey(),
			Addresses: []netip.Prefix{lb.addrPrefix},
			HomeDERP:  derpRegion,
		}).View()
		nm.Peers = append(nm.Peers, (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.tailcat.",
			User:       100,
			Key:        lb.serverPub,
			DiscoKey:   nodePublicAsDiscoPublic(lb.serverPub),
			Addresses:  []netip.Prefix{serverAddrPrefix},
			AllowedIPs: []netip.Prefix{serverAddrPrefix, allIPv6},
			HomeDERP:   derpRegion,
		}).View())
	}
	lb.mu.Lock()
	lb.nm = nm
	lb.mu.Unlock()

	mc.SetNetworkMap(nm.SelfNode, nm.Peers)
	lb.sys.Netstack.Get().UpdateNetstackIPs(nm)
	mc.SetNetworkUp(true)
	lb.logf("NetworkMap: %v", logger.AsJSON(nm))

	// Install the live per-peer config sources. WireGuard peers are
	// created lazily from these as traffic arrives; there is no
	// peer list in wgcfg.Config anymore.
	e.SetPeerConfigFunc(lb.peerAllowedIPs)
	e.SetPeerByIPPacketFunc(lb.peerByIP)

	wgConf := &wgcfg.Config{
		PrivateKey: lb.priv,
		Addresses:  []netip.Prefix{lb.addrPrefix},
	}
	if lb.serverPub.IsZero() {
		// We're the server.
		wgConf.Addresses = append(wgConf.Addresses, allIPv6)
	}
	routerConf := &router.Config{
		LocalAddrs: []netip.Prefix{lb.addrPrefix},
	}
	dnsConf := &dns.Config{}
	if err := e.Reconfig(wgConf, routerConf, dnsConf); err != nil {
		return fmt.Errorf("e.Reconfig: %w", err)
	}
	lb.sys.NetMon.Get().Start()

	return nil
}

// onMeow handles a MeowPing from the client with node key src and
// disco key discoPub, adding it as a WireGuard peer. The allowed
// result reports whether the client is allowed and configured,
// meaning a "meowed" acknowledgment may be sent. The isNew result
// reports whether this call added the client, as opposed to it
// already being a peer from an earlier meow.
func (b *locoBackend) onMeow(src key.NodePublic, discoPub key.DiscoPublic) (allowed, isNew bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.logf("got meow from %v", src.String())
	if b.allowedClients != nil && !b.allowedClients[src] {
		b.logf("ignoring meow from %v: not in allowedClients", src.String())
		return false, false
	}

	if _, ok := b.clients[src]; ok {
		return true, false
	}
	id := len(b.clients) + 2 // server is ID 1, clients are IDs 2, 3, ...
	derpRegion := b.derpRegionID()
	mak.Set(&b.clients, src, &tailcfg.Node{
		ID:         tailcfg.NodeID(id),
		StableID:   tailcfg.StableNodeID(fmt.Sprint(id)),
		Name:       fmt.Sprintf("client%d.tailcat.", id),
		User:       100,
		Key:        src,
		DiscoKey:   discoPub,
		Addresses:  []netip.Prefix{pfxOf(tcAddrForKey(src))},
		AllowedIPs: []netip.Prefix{pfxOf(tcAddrForKey(src))},
		HomeDERP:   derpRegion,
	})

	nm := &netmap.NetworkMap{
		NodeKey: b.pub,
		SelfNode: (&tailcfg.Node{
			ID:         1,
			StableID:   "1",
			Name:       "server.tailcat.",
			User:       100,
			Key:        b.pub,
			DiscoKey:   b.discoPublic(),
			Addresses:  []netip.Prefix{b.addrPrefix},
			AllowedIPs: []netip.Prefix{b.addrPrefix, allIPv6},
			HomeDERP:   derpRegion,
		}).View(),
	}
	for _, n := range b.clients {
		nm.Peers = append(nm.Peers, n.View())
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	b.nm = nm

	mc := b.sys.MagicSock.Get()
	mc.SetNetworkMap(nm.SelfNode, nm.Peers)
	b.sys.Netstack.Get().UpdateNetstackIPs(nm)

	// No engine reconfig needed: the WireGuard device learns about the
	// new peer lazily via the config source installed with
	// SetPeerConfigFunc when the client's handshake arrives.
	return true, true
}

func (b *locoBackend) Status() *ipnstate.Status {
	mc := b.sys.MagicSock.Get()
	eng := b.sys.Engine.Get()
	var sb ipnstate.StatusBuilder
	mc.UpdateStatus(&sb)
	eng.UpdateStatus(&sb)
	return sb.Status()
}

func tcAddrForKey(k key.NodePublic) netip.Addr {
	var a [16]byte
	r := k.Raw32()
	// Use Tailscale's ULA range fd7a:115c:a1e0::/48, filling the
	// remaining 80 bits from the node key.
	a[0] = 0xfd
	a[1] = 0x7a
	a[2] = 0x11
	a[3] = 0x5c
	a[4] = 0xa1
	a[5] = 0xe0
	copy(a[6:], r[:10])
	return netip.AddrFrom16(a)
}

func newNetstack(logf logger.Logf, sys *tsd.System) (*netstack.Impl, error) {
	return netstack.Create(logf,
		sys.Tun.Get(),
		sys.Engine.Get(),
		sys.MagicSock.Get(),
		sys.Dialer.Get(),
		sys.DNSManager.Get(),
		sys.ProxyMapper(),
	)
}

// createEngine creates the wgengine.Engine with userspace networking.
func createEngine(logf logger.Logf, lb *locoBackend) (err error) {
	sys := &lb.sys
	conf := wgengine.Config{
		ListenPort:    0,
		NetMon:        sys.NetMon.Get(),
		Dialer:        sys.Dialer.Get(),
		SetSubsystem:  sys.Set,
		Metrics:       sys.UserMetricsRegistry(),
		HealthTracker: sys.HealthTracker.Get(),
		EventBus:      sys.Bus.Get(),
		OnDERPRecv:    lb.onDERPRecv,
		DERPAppName:   "tailcat-client",
	}
	if lb.isServer {
		conf.DERPAppName = "tailcat-server"
		// The server forces its disco key to be derived from its node key
		// so clients can predict it from the ConnBlob without extra round trips.
		conf.ForceDiscoKey = nodePrivateAsDiscoPrivate(lb.priv)
	}
	netns.SetEnabled(false)
	e, err := wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", "userspace-networking", err)
		return err
	}
	sys.Set(e)
	sys.NetstackRouter.Set(true)
	return nil
}

// Client connects to a [Server] over a WireGuard tunnel relayed through DERP.
// After creating a Client with [NewClient], just dial: [Client.Dial],
// [Client.DialTCPPort], and [Client.DialTCP] lazily establish the tunnel on
// first use. [Client.Ping] does the same and is useful to test connectivity
// first or to measure the relay round-trip time.
type Client struct {
	// DERPMapURL, if non-empty, is an alternate URL to fetch the DERP
	// map from when the ConnBlob doesn't embed the relay details.
	// If empty, [DefaultDERPMapURL] is used. It must be set before the
	// client's first use.
	DERPMapURL string

	lb       *locoBackend
	ci       ConnInfo      // of server
	meowWait chan struct{} // closed on first meowed message from server

	serverAddr netip.Addr

	startMu sync.Mutex // guards started and the one-time startup work
	started bool

	upDone atomic.Bool // whether the server has meowed us at least once
}

// NewClient creates a client that will connect to the server identified by the
// given [ConnBlob]. The priv key is the client's own node identity.
//
// NewClient does no network access; the tunnel is established lazily
// by the first Dial or [Client.Ping] call, which also resolves the
// DERP region if the ConnBlob references it by ID rather than
// embedding it.
func NewClient(logf logger.Logf, server ConnBlob, priv key.NodePrivate) (*Client, error) {
	ci, err := ParseConnBlob(server)
	if err != nil {
		return nil, err
	}

	lb := newLocoBackend(priv)
	lb.logf = logf
	lb.dm = &tailcfg.DERPMap{}
	lb.serverPub = ci.ServerPublic.NodePublic

	sys := &lb.sys
	bus := eventbus.New()
	sys.Set(bus)
	sys.Set(health.NewTracker(bus))

	netMon, err := netmon.New(bus, func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return nil, fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)

	var store ipn.StateStore = new(mem.Store)
	sys.Set(store)

	meowWait := make(chan struct{})
	onMeowed := sync.OnceFunc(func() { close(meowWait) })
	lb.onDERPRecv = func(regionID int, src key.NodePublic, pkt []byte) bool {
		if !IsMeowPacket(pkt) {
			return false
		}
		if IsMeowedPacket(pkt) {
			go onMeowed()
			return true
		}
		return true // client ignores MeowPing
	}

	if err := createEngine(logf, lb); err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	ns, err := newNetstack(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = true // required to even reply to TCP SYNs client sends out
	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		return nil, true // don't accept any incoming connections to client
	}
	lb.ns = ns
	sys.Set(ns)

	e := sys.Engine.Get()
	// The client accepts no new inbound connections at all: the filter
	// admits only continuations of client-initiated TCP flows (the
	// filter always passes non-SYN TCP segments to addresses in its
	// local set, and outbound traffic is never filtered).
	localNets := new(netipx.IPSetBuilder)
	localNets.AddPrefix(lb.addrPrefix)
	local, _ := localNets.IPSet()
	e.SetFilter(filter.New(nil, nil, local, nil, nil, logf))
	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := lb.peerByIP(ip)
		return ok
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}
	dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		panic("unreachable from tailcat") // but required by Dialer currently
	}
	sys.Tun.Get().Start()

	return &Client{
		ci:         ci,
		lb:         lb,
		serverAddr: tcAddrForKey(ci.ServerPublic.NodePublic),
		meowWait:   meowWait,
	}, nil
}

// PublicKey returns the client's node public key.
func (c *Client) PublicKey() key.NodePublic { return c.lb.pub }

// Connected returns a channel that is closed once the server has
// acknowledged this client via the meow handshake, meaning the
// tunnel is ready for dialing. The handshake happens implicitly on
// the first Dial or [Client.Ping] call.
func (c *Client) Connected() <-chan struct{} { return c.meowWait }

// Close shuts down the client, closing the WireGuard engine and DERP connections.
func (c *Client) Close() error { return c.lb.Close() }

// PingResult is the result of a successful [Client.Ping] call.
type PingResult struct {
	// Latency is the round-trip time for the meow/meowed handshake
	// through the DERP relay.
	Latency time.Duration
}

// ensureStarted brings up the client's network stack on first use:
// it resolves the server's DERP region if the ConnBlob didn't embed
// it (possibly fetching the DERP map over the network, bounded by
// ctx; see [ConnBlob.Resolve] to do that step earlier), connects to
// the DERP relay, and configures WireGuard. Failed attempts are
// retried on the next call.
func (c *Client) ensureStarted(ctx context.Context) error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.started {
		return nil
	}
	var opts []any
	if c.DERPMapURL != "" {
		opts = append(opts, DERPMapURL(c.DERPMapURL))
	}
	if err := c.ci.Expand(ctx, opts...); err != nil {
		return err
	}
	if len(c.ci.Region) == 0 {
		return errors.New("no DERP regions in ConnBlob")
	}
	for _, r := range c.ci.Region {
		mak.Set(&c.lb.dm.Regions, r.RegionID, r)
	}
	if err := c.lb.Start(); err != nil {
		return err
	}
	c.started = true
	return nil
}

// up ensures the client is started and the server has acknowledged
// us as a peer, performing the meow handshake on first use. Dial
// methods call it so that a fresh Client can dial directly with no
// setup calls. A concurrent first use may ping twice; the handshake
// is idempotent.
func (c *Client) up(ctx context.Context) error {
	if c.upDone.Load() {
		return nil
	}
	_, err := c.Ping(ctx)
	return err
}

// Ping starts the client if needed (see [Client.Dial] for the lazy
// startup behavior), sends a meow ping to the server via DERP, and
// waits for the meowed acknowledgment, which also tells the server
// to add us as a WireGuard peer. Calling it is optional (Dial does
// it implicitly) but useful to test connectivity or measure the
// relay round-trip time. The internal timeout is 10 seconds
// regardless of ctx.
func (c *Client) Ping(ctx context.Context) (PingResult, error) {
	var zero PingResult
	if err := c.ensureStarted(ctx); err != nil {
		return zero, err
	}
	res, err := c.ping(ctx)
	if err == nil {
		c.upDone.Store(true)
	}
	return res, err
}

// ping sends a single meow ping and waits for the meowed ack. The
// client must be started.
func (c *Client) ping(ctx context.Context) (PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var zero PingResult
	t0 := time.Now()
	mc := c.lb.sys.MagicSock.Get()

	dstNode := c.ci.ServerPublic.NodePublic
	derpRegion := c.lb.derpRegionID()
	pkt := EncodeMeowPing(c.lb.pub, mc.DiscoPublicKey())

	sent, err := mc.SendDERPPacketTo(dstNode, derpRegion, pkt)
	if err != nil {
		return zero, fmt.Errorf("sending meow: %w", err)
	}
	if !sent {
		return zero, fmt.Errorf("meow not sent")
	}

	select {
	case <-c.meowWait:
		return PingResult{time.Since(t0)}, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

// Dial opens a connection to the given network/address through the server's
// WireGuard tunnel. The address is resolved relative to the server.
//
// On a Client's first use (any Dial method or [Client.Ping]), the
// client lazily brings up its network stack, resolving the server's
// DERP region over the network if the ConnBlob didn't embed it, and
// registers itself with the server.
func (c *Client) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := c.up(ctx); err != nil {
		return nil, err
	}
	return c.lb.sys.Dialer.Get().UserDial(ctx, network, addr)
}

// DialTCPPort opens a TCP connection to the given port on the server.
// See [Client.Dial] for the lazy startup behavior.
func (c *Client) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	if err := c.up(ctx); err != nil {
		return nil, err
	}
	return c.lb.sys.Dialer.Get().UserDial(ctx, "tcp", net.JoinHostPort(c.serverAddr.String(), fmt.Sprint(port)))
}

var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	nat64PrefixBytes = nat64Prefix.Addr().As16()
)

// DialTCP opens a TCP connection to an arbitrary IP:port through the server,
// which must be configured as an exit node (see [Server.OnTCPForward]).
// IPv4 addresses are mapped into the NAT64 prefix (64:ff9b::/96) for
// transport over the IPv6-only WireGuard tunnel.
// See [Client.Dial] for the lazy startup behavior.
func (c *Client) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if err := c.up(ctx); err != nil {
		return nil, err
	}
	if ap.Addr().Is4() {
		a := nat64PrefixBytes
		a4 := ap.Addr().As4()
		copy(a[12:], a4[:])
		ap = netip.AddrPortFrom(netip.AddrFrom16(a), ap.Port())
	}
	return c.lb.ns.DialContextTCP(ctx, ap)
}

func pfxOf(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// closeWriter is implemented by TCP-like connections (such as
// [net.TCPConn] and gVisor's gonet.TCPConn) that can shut down just
// their writing side.
type closeWriter interface {
	CloseWrite() error
}

// ProxyConns copies data between a and b in both directions until
// both sides have finished, then closes both connections.
//
// When one direction's copy finishes (its source reached EOF), the
// destination gets a write shutdown via CloseWrite if supported,
// propagating the TCP half-close instead of tearing down the whole
// connection. This lets protocols where one side signals
// end-of-request with a FIN and then reads the response (netcat
// style) work through the proxy.
func ProxyConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// Status returns the current WireGuard and DERP connection status.
func (s *Server) Status() *ipnstate.Status {
	return s.lb.Status()
}

// nodePrivateAsDiscoPrivate converts a NodePrivate to a DiscoPrivate by
// reusing the same raw key bytes. This is used in tailcat where the server
// uses its node key as the disco key.
func nodePrivateAsDiscoPrivate(k key.NodePrivate) key.DiscoPrivate {
	raw := k.Raw32()
	return key.DiscoPrivateFromRaw32(go4mem.B(raw[:]))
}

// nodePublicAsDiscoPublic converts a NodePublic to a DiscoPublic by
// reusing the same raw key bytes. This is used in tailcat where the
// server's node public key doubles as its disco public key.
func nodePublicAsDiscoPublic(k key.NodePublic) key.DiscoPublic {
	raw := k.Raw32()
	return key.DiscoPublicFromRaw32(go4mem.B(raw[:]))
}
