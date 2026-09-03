// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"go4.org/mem"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

const testNICID = 1

func newTestTCPStack(t *testing.T, addr tcpip.Address) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(16, 1500, "")
	if err := s.CreateNIC(testNICID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	if err := s.AddProtocolAddress(testNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: testNICID}})
	t.Cleanup(func() {
		ep.Close()
		s.Close()
		s.Wait()
	})
	return s, ep
}

func relayTestPackets(ctx context.Context, src, dst *channel.Endpoint, packet func(*stack.PacketBuffer) bool) {
	for {
		pkt := src.ReadContext(ctx)
		if pkt == nil {
			return
		}
		forward := packet == nil || packet(pkt)
		if forward {
			in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pkt.ToBuffer()})
			dst.InjectInbound(pkt.NetworkProtocolNumber, in)
			in.DecRef()
		}
		pkt.DecRef()
	}
}

func testPacketTCPFlags(pkt *stack.PacketBuffer) header.TCPFlags {
	v := pkt.ToView()
	defer v.Release()
	ip := header.IPv4(v.AsSlice())
	if ip.TransportProtocol() != tcp.ProtocolNumber {
		return 0
	}
	return header.TCP(ip[ip.HeaderLength():]).Flags()
}

type testTCPStateEndpoint interface {
	tcpStateEndpoint
	LockUser()
	UnlockUser()
}

func checkTestTCPState(t *testing.T, c *gonet.TCPConn, want tcp.EndpointState) {
	t.Helper()
	ep, _ := gonetTCPConnInternals(c)
	lep := ep.(testTCPStateEndpoint)
	lep.LockUser()
	got := tcp.EndpointState(ep.State())
	lep.UnlockUser()
	if got != want {
		t.Fatalf("TCP state = %v; want %v", got, want)
	}
}

func TestCloseProxyConnRetransmitsFIN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clientAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	serverAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
	clientStack, clientLink := newTestTCPStack(t, clientAddr)
	serverStack, serverLink := newTestTCPStack(t, serverAddr)

	go relayTestPackets(ctx, clientLink, serverLink, nil)
	firstServerFIN := make(chan struct{})
	secondServerFIN := make(chan struct{})
	finCount := 0
	go relayTestPackets(ctx, serverLink, clientLink, func(pkt *stack.PacketBuffer) bool {
		if testPacketTCPFlags(pkt)&header.TCPFlagFin == 0 {
			return true
		}
		finCount++
		switch finCount {
		case 1:
			close(firstServerFIN)
			return false
		case 2:
			close(secondServerFIN)
		}
		return true
	})

	ln, err := gonet.ListenTCP(serverStack, tcpip.FullAddress{
		NIC:  testNICID,
		Addr: serverAddr,
		Port: 1234,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *gonet.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c.(*gonet.TCPConn)
	}()
	client, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC:  testNICID,
		Addr: serverAddr,
		Port: 1234,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	server := <-accepted

	// Put the server in LAST-ACK: first receive the client's FIN, then send
	// the server FIN. The packet relay deliberately drops that first FIN.
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	if _, err := io.Copy(io.Discard, server); err != nil {
		t.Fatalf("server read to EOF: %v", err)
	}
	checkTestTCPState(t, server, tcp.StateCloseWait)
	if err := server.CloseWrite(); err != nil {
		t.Fatalf("server CloseWrite: %v", err)
	}
	select {
	case <-firstServerFIN:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not send its first FIN")
	}

	closed := make(chan struct{})
	go func() {
		closeProxyConnTimeout(server, time.Second)
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("closeProxyConn returned before the dropped FIN was retransmitted")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-secondServerFIN:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not retransmit its FIN")
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("client SetReadDeadline: %v", err)
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("client read after retransmitted FIN = %d, %v; want 0, EOF", n, err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		sep, _ := gonetTCPConnInternals(server)
		cep, _ := gonetTCPConnInternals(client)
		t.Logf("states: server=%v client=%v", tcp.EndpointState(sep.State()), tcp.EndpointState(cep.State()))
		t.Fatal("closeProxyConn did not return after the retransmitted FIN was acknowledged")
	}
}

func mkLogger(t testing.TB, name string) logger.Logf {
	return func(format string, args ...any) {
		t.Helper()
		if t.Failed() {
			return
		}
		t.Logf("        ["+name+"] "+format, args...)
	}
}

func TestTailcat(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	t.Logf("DERPMap: %v", logger.AsJSON(dm))

	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}
	priv := key.NewNode()

	s := &Server{Key: priv, Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		t.Logf("test: OnTCP(port %v) ...", port)
		if port != 80 {
			return nil
		}
		return func(c net.Conn) {
			io.WriteString(c, "Hello from port 80\n")
			c.Close()
		}
	}
	s.OnTCPForward = func(dst netip.AddrPort) (handler func(net.Conn)) {
		t.Logf("test: OnTCPForward(%v) ...", dst)
		return func(c net.Conn) {
			io.WriteString(c, "Hello from relay\n")
			c.Close()
		}
	}
	// Start with a non-matching allowlist entry so the first ping can verify
	// that disallowed clients get no acknowledgement.
	s.AddAllowedClient(key.NewNode().Public())

	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	t.Logf("server: %v", s.TailcatAddr())

	c := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })

	t.Logf("Client is %v", c.PublicKey())

	WaitForDERPForTest(t, s, c)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if _, err := c.Ping(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping from disallowed client = %v; want context deadline exceeded", err)
	}
	cancel()
	s.AddAllowedClient(c.PublicKey())

	pi := PingForTest(t, s, c)
	t.Logf("got ping: %+v", pi)

	// No sleep here: a successful Ping means the server has fully
	// added us as a peer and we may dial immediately.

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("UserDial = %v, %v", conn, err)
	}
	all, err := io.ReadAll(conn)
	t.Logf("Got: %q, %v", all, err)

	// And dialing arbitrary IPs...
	conn, err = c.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.1:123"))
	if err != nil {
		t.Fatalf("DialTCP = %v, %v", conn, err)
	}

}

// TestHalfClose tests that a client's write shutdown (CloseWrite)
// propagates through the server's TCP proxying as a half-close
// rather than tearing down the whole connection: the backend must
// still be able to send its response after seeing the client's EOF,
// netcat style.
func TestHalfClose(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	// The backend reads until EOF and only then writes its response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				got, err := io.ReadAll(c)
				if err != nil {
					t.Logf("backend read: %v", err)
					return
				}
				fmt.Fprintf(c, "read %d bytes", len(got))
			}()
		}
	}()

	s := &Server{Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		return func(c net.Conn) {
			backend, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Logf("backend dial: %v", err)
				c.Close()
				return
			}
			ProxyConns(c, backend)
		}
	}
	s.ServedTCPPorts = []filter.PortRange{{First: 80, Last: 80}}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	c := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	defer conn.Close()

	const req = "hello, backend"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("conn type %T doesn't support CloseWrite", conn)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading response after half-close: %v", err)
	}
	if want := fmt.Sprintf("read %d bytes", len(req)); string(resp) != want {
		t.Fatalf("response = %q; want %q", resp, want)
	}

	// The packet filter (ServedTCPPorts) must drop SYNs to unserved
	// ports before they reach OnTCP, whose handler above would accept
	// any port. A filter drop is silent, so the dial must ride out
	// the context deadline rather than fail fast with a RST.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	c2, err := c.DialTCPPort(ctx2, 81)
	if err == nil {
		c2.Close()
		t.Fatal("dial to filtered port 81 unexpectedly succeeded")
	}
	if ctx2.Err() == nil {
		t.Fatalf("dial to filtered port 81 failed fast (%v); want silent drop until context deadline", err)
	}
}

func TestServerCloseClosesActiveConnections(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	clientKey := key.NewNode()
	accepted := make(chan net.Conn, 1)
	handlerDone := make(chan struct{})
	s := &Server{
		Logf:           mkLogger(t, "server"),
		Region:         reg,
		AllowedClients: []key.NodePublic{clientKey.Public()},
		ServedTCPPorts: []filter.PortRange{{First: 80, Last: 80}},
		OnTCP: func(port uint16) func(net.Conn) {
			if port != 80 {
				return nil
			}
			return func(conn net.Conn) {
				accepted <- conn
				defer close(handlerDone)
				var buf [1]byte
				_, _ = conn.Read(buf[:])
			}
		},
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	c := &Client{Server: s.TailcatAddr(), Key: clientKey, Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientConn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
		t.Cleanup(func() { serverConn.Close() })
	case <-ctx.Done():
		t.Fatalf("waiting for accepted connection: %v", ctx.Err())
	}

	if err := s.Close(); err != nil {
		t.Fatalf("server Close: %v", err)
	}

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server Close left an active netstack connection open")
	}
}

func TestAddr(t *testing.T) {
	akey := func(a [32]byte) NodePublic {
		return NodePublic{key.NodePublicFromRaw32(mem.B(a[:]))}
	}
	tests := []struct {
		name string
		ci   ConnInfo
		want Addr      // if non-empty, check exact encoding
		back *ConnInfo // if non-nil, round-tripped form we want
	}{
		{
			name: "just_key",
			ci: ConnInfo{
				ServerPublic: akey([32]byte{1: 1, 2: 2, 31: 31}),
			},
			want: "tcoWFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHw",
		},
		{
			name: "key_with_full_custom_region",
			ci: ConnInfo{
				ServerPublic: akey([32]byte{1: 1, 2: 2, 31: 31}),
				Region: []*tailcfg.DERPRegion{
					{
						Nodes: []*tailcfg.DERPNode{
							{
								Name:     "1a",
								IPv4:     "400.400.400.400",
								HostName: "my-derp.custom.example",
							},
							{
								Name:     "1b",
								IPv4:     "400.400.400.400",
								HostName: "my-derp2.custom.example",
							},
						},
					},
				},
			},
			back: &ConnInfo{
				ServerPublic: akey([32]byte{1: 1, 2: 2, 31: 31}),
				Region: []*tailcfg.DERPRegion{
					{
						RegionID:   1,
						RegionCode: "1",
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 1,
								Name:     "my-derp.custom.example",
								IPv4:     "400.400.400.400",
								HostName: "my-derp.custom.example",
							},
							{
								RegionID: 1,
								Name:     "my-derp2.custom.example",
								IPv4:     "400.400.400.400",
								HostName: "my-derp2.custom.example",
							},
						},
					},
				},
			},
		},

		{
			name: "remove_implicit_fields_on_marshal",
			ci: ConnInfo{
				ServerPublic: akey([32]byte{1: 1, 2: 2, 31: 31}),
				Region: []*tailcfg.DERPRegion{
					{
						RegionID:   123,
						RegionName: "Seattle",
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 123,
								Name:     "1a",
								HostName: "tc1a.ipn.dev",
							},
							{
								RegionID: 123,
								Name:     "1b",
								HostName: "derp1b.tailscale.com",
							},
						},
					},
				},
			},
			back: &ConnInfo{
				ServerPublic: akey([32]byte{1: 1, 2: 2, 31: 31}),
				Region: []*tailcfg.DERPRegion{
					{
						RegionID:   1,
						RegionCode: "1",
						Nodes: []*tailcfg.DERPNode{
							{
								RegionID: 1,
								Name:     "tc1a.ipn.dev",
								HostName: "tc1a.ipn.dev",
							},
							{
								RegionID: 1,
								Name:     "derp1b.tailscale.com",
								HostName: "derp1b.tailscale.com",
							},
						},
					},
				},
			},
		},

		{
			name: "region_id",
			ci: ConnInfo{
				ServerPublic: akey([32]byte{1: 1, 2: 2, 31: 31}),
				RegionID:     10,
			},
			want: "tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ci.Addr()
			t.Logf("length: %v (%v)", len(got), got)
			if tt.want != "" && got != tt.want {
				t.Fatalf("ConnInfo.Addr marshal wrong.\n got: %s\nwant: %s\n", got, tt.want)
			}

			gotCI, err := ParseAddr(got)
			if err != nil {
				t.Fatalf("ParseAddr: %v", err)
			}
			want := tt.ci
			if tt.back != nil {
				want = *tt.back
			}
			if diff := cmp.Diff(want, gotCI); diff != "" {
				t.Errorf("ParseAddr result back diff:\n%s", diff)
			}
		})
	}
}

func TestAddrSeparateDiscoKey(t *testing.T) {
	priv := key.NewNode()
	discoPub := DiscoPublicForNode(priv)
	ci := ConnInfo{
		ServerPublic:      NodePublic{priv.Public()},
		ServerDiscoPublic: discoPub,
		RegionID:          10,
	}
	got, err := ParseAddr(ci.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if !got.ServerDiscoPublic.Equal(discoPub) {
		t.Fatalf("disco public key changed in round trip: got %v, want %v", got.ServerDiscoPublic, discoPub)
	}
	if got.ServerDiscoPublic.Raw32() == got.ServerPublic.Raw32() {
		t.Fatal("server disco public key exposes the server node public key")
	}
	if again := DiscoPublicForNode(priv); !again.Equal(discoPub) {
		t.Fatal("disco key derivation is not stable")
	}
	// Reproduce the report's reconstruction strategy: treating the public
	// key visible in a direct-path disco frame as the server node key must
	// not recover the tailcat address.
	reconstructed := (&ConnInfo{
		ServerPublic: NodePublic{key.NodePublicFromRaw32(mem.B(discoPub.AppendTo(nil)))},
		RegionID:     ci.RegionID,
	}).Addr()
	if reconstructed == ci.Addr() {
		t.Fatal("disco public key can reconstruct the tailcat address")
	}
}

func TestClientRejectsLegacyAddr(t *testing.T) {
	legacy := (&ConnInfo{
		ServerPublic: NodePublic{key.NewNode().Public()},
		RegionID:     10,
	}).Addr()
	c := NewClient(legacy)
	_, err := c.Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "legacy tailcat address") {
		t.Fatalf("Ping error = %v; want legacy address rejection", err)
	}
}

func TestParseAddrMalformedPublicKey(t *testing.T) {
	for name, keyBytes := range map[string][]byte{
		"short": make([]byte, key.NodePublicRawLen-1),
		"long":  make([]byte, key.NodePublicRawLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := cbor.Marshal(map[string][]byte{"p": keyBytes})
			if err != nil {
				t.Fatal(err)
			}
			addr := Addr("tc" + base64.RawURLEncoding.EncodeToString(raw))
			assertParseError := func(name string, parse func() error) {
				t.Helper()
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s panicked: %v", name, r)
					}
				}()
				if err := parse(); err == nil {
					t.Errorf("%s unexpectedly accepted malformed public key", name)
				}
			}
			assertParseError("ParseAddr", func() error {
				_, err := ParseAddr(addr)
				return err
			})
			assertParseError("ParseAddrRaw", func() error {
				_, err := ParseAddrRaw(addr)
				return err
			})
		})
	}
}

func TestParseAddrMalformedDiscoPublicKey(t *testing.T) {
	for name, keyBytes := range map[string][]byte{
		"short": make([]byte, key.DiscoPublicRawLen-1),
		"long":  make([]byte, key.DiscoPublicRawLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := cbor.Marshal(map[string][]byte{
				"p": key.NewNode().Public().AppendTo(nil),
				"k": keyBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			addr := Addr("tc" + base64.RawURLEncoding.EncodeToString(raw))
			if _, err := ParseAddr(addr); err == nil {
				t.Fatal("ParseAddr unexpectedly accepted malformed disco public key")
			}
		})
	}
}

// TestFetchDERPMapMemoryCache verifies the default in-memory DERP map
// cache: a second fetch of the same URL within the freshness window
// makes no network request.
func TestFetchDERPMapMemoryCache(t *testing.T) {
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		fmt.Fprint(w, `{"Regions":{"1":{"RegionID":1}}}`)
	}))
	defer srv.Close()

	for range 2 {
		dm, err := FetchDERPMap(context.Background(), DERPMapURL(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		if len(dm.Regions) != 1 {
			t.Fatalf("got %d regions; want 1", len(dm.Regions))
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Errorf("fetches = %d; want 1", n)
	}
}

// TestParseAddrNullInArrays checks that ParseAddr rejects addresses whose
// region or node arrays contain a CBOR null. Those decode to nil pointers, and
// before this was checked they panicked when dereferenced. Addrs come from
// untrusted places, so a panic here takes down the process.
func TestParseAddrNullInArrays(t *testing.T) {
	addr := func(t *testing.T, m map[string]any) Addr {
		t.Helper()
		b, err := cbor.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return Addr("tc" + base64.RawURLEncoding.EncodeToString(b))
	}
	pub := key.NewNode().Public().AppendTo(nil)

	tests := []struct {
		name string
		addr Addr
	}{
		{
			name: "null_region",
			addr: addr(t, map[string]any{"p": pub, "r": []any{nil}}),
		},
		{
			name: "null_node",
			addr: addr(t, map[string]any{"p": pub, "r": []any{
				map[string]any{"i": 1, "N": []any{nil}},
			}}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseAddr(tt.addr); err == nil {
				t.Fatal("ParseAddr succeeded; want an error")
			}
		})
	}
}

// TestParseAddrRawKeepsNulls documents that the raw form stays permissive:
// "tailcat parse" is a diagnostic for looking at a broken address, so it shows the
// nulls instead of rejecting them.
func TestParseAddrRawKeepsNulls(t *testing.T) {
	b, err := cbor.Marshal(map[string]any{
		"p": key.NewNode().Public().AppendTo(nil),
		"r": []any{nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := Addr("tc" + base64.RawURLEncoding.EncodeToString(b))
	got, err := ParseAddrRaw(addr)
	if err != nil {
		t.Fatalf("ParseAddrRaw: %v", err)
	}
	w, ok := got.(*wireConnInfo)
	if !ok {
		t.Fatalf("got %T; want *wireConnInfo", got)
	}
	if len(w.Region) != 1 || w.Region[0] != nil {
		t.Errorf("Region = %v; want a single nil element", w.Region)
	}
}
