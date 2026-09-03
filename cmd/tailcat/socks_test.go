// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/net/socks5"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

func TestClassifySOCKSAddr(t *testing.T) {
	ap := netip.MustParseAddrPort
	noLookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("unexpected lookup of %q", host)
	}
	lookupOf := func(ips ...string) func(context.Context, string) ([]netip.Addr, error) {
		return func(ctx context.Context, host string) ([]netip.Addr, error) {
			var ret []netip.Addr
			for _, s := range ips {
				ret = append(ret, netip.MustParseAddr(s))
			}
			return ret, nil
		}
	}

	tests := []struct {
		name    string
		addr    string
		lookup  func(context.Context, string) ([]netip.Addr, error)
		want    socksTarget
		wantErr bool
	}{
		{
			name:   "server_magic_name",
			addr:   "server.tailcat:8081",
			lookup: noLookup,
			want:   socksTarget{toServer: true, port: 8081},
		},
		{
			name:   "empty_host",
			addr:   ":80",
			lookup: noLookup,
			want:   socksTarget{toServer: true, port: 80},
		},
		{
			name:   "addr_host",
			addr:   "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu:8081",
			lookup: noLookup,
			want: socksTarget{
				addr: "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu",
				port: 8081,
			},
		},
		{
			name:   "tc_prefixed_non_addr_host_uses_lookup",
			addr:   "tcserver:80",
			lookup: lookupOf("192.0.2.1"),
			want:   socksTarget{dst: ap("192.0.2.1:80")},
		},
		{
			name:   "ipv4_literal",
			addr:   "10.1.2.3:80",
			lookup: noLookup,
			want:   socksTarget{dst: ap("10.1.2.3:80")},
		},
		{
			name:   "ipv6_literal",
			addr:   "[2001:db8::1]:443",
			lookup: noLookup,
			want:   socksTarget{dst: ap("[2001:db8::1]:443")},
		},
		{
			name:   "ipv4_mapped_literal_unmapped",
			addr:   "[::ffff:1.2.3.4]:80",
			lookup: noLookup,
			want:   socksTarget{dst: ap("1.2.3.4:80")},
		},
		{
			name:   "hostname_prefers_ipv4",
			addr:   "example.com:80",
			lookup: lookupOf("2001:db8::1", "192.0.2.1"),
			want:   socksTarget{dst: ap("192.0.2.1:80")},
		},
		{
			name:   "hostname_ipv6_only",
			addr:   "example.com:80",
			lookup: lookupOf("2001:db8::1"),
			want:   socksTarget{dst: ap("[2001:db8::1]:80")},
		},
		{
			name: "hostname_lookup_error",
			addr: "example.com:80",
			lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return nil, errors.New("nope")
			},
			wantErr: true,
		},
		{
			name:    "hostname_no_addresses",
			addr:    "example.com:80",
			lookup:  lookupOf(),
			wantErr: true,
		},
		{
			name:    "missing_port",
			addr:    "example.com",
			lookup:  noLookup,
			wantErr: true,
		},
		{
			name:    "bad_port",
			addr:    "example.com:99999",
			lookup:  noLookup,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifySOCKSAddr(context.Background(), tt.lookup, tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("classifySOCKSAddr(%q) = %+v; want error", tt.addr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("classifySOCKSAddr(%q): %v", tt.addr, err)
			}
			if got != tt.want {
				t.Fatalf("classifySOCKSAddr(%q) = %+v; want %+v", tt.addr, got, tt.want)
			}
		})
	}
}

// TestSOCKSClientKey verifies that "tailcat socks" presents the
// --key client identity rather than a fresh ephemeral node key, by
// connecting to a server that only allows that identity. Before this
// test existed, socks mode ignored --key and could never reach a
// server locked down with --allow (issue #24).
func TestSOCKSClientKey(t *testing.T) {
	e := newTestEnv(t)

	clientKey := filepath.Join(t.TempDir(), "c.private.json")
	if out, err := e.cmd("genkey", "--client", "--key="+clientKey).CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}
	pub, err := e.cmd("--key="+clientKey, "printpub").Output()
	if err != nil {
		t.Fatalf("printpub: %v", err)
	}
	cpub := strings.TrimSpace(string(pub))

	_, addr, _ := e.startServer("serve", "--allow="+cpub, "all")

	// The socks client pings the server before starting the proxy and
	// exits non-zero if the ping fails, so a successful run of a
	// trivial child command proves the allowlisted handshake worked.
	args := append([]string{"--key=" + clientKey, "--derpmap-url=" + e.derpMapURL, "socks", addr}, testNoopCommand()...)
	client := e.cmd(args...)
	if out, err := client.CombinedOutput(); err != nil {
		t.Fatalf("socks with allowlisted --key failed: %v\n%s", err, out)
	}
}

func TestNormalizeListenAddrPort(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "integer only",
			input: "1234",
			want:  "127.0.0.1:1234",
		},
		{
			name:  "omit address means all interfaces",
			input: ":1234",
			want:  ":1234",
		},
		{
			name:  "omit port with IPv4 address",
			input: "127.0.0.1",
			want:  "127.0.0.1:0",
		},
		{
			name:  "omit port with IPv6 address",
			input: "[2001:db8::1]",
			want:  "[2001:db8::1]:0",
		},
		{
			name:  "others",
			input: "foo",
			want:  "foo:0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeListenAddrPort(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeListenAddrPort(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestDialSOCKSTarget exercises the SOCKS dialer used by "tailcat socks"
// against a live server: UDP ASSOCIATE targets must ride the tailcat UDP
// APIs (DialUDPPort/DialUDP) while TCP keeps using the TCP dialers.
func TestDialSOCKSTarget(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, testLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := backend.WriteToUDP(buf[:n], src); err != nil {
				return
			}
		}
	}()
	backendAddr := backend.LocalAddr().(*net.UDPAddr).AddrPort()

	s := &tailcat.Server{Logf: testLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnUDP = func(port uint16) func(tailcat.ConnPacketConn) {
		if port != 53 {
			return nil
		}
		return func(c tailcat.ConnPacketConn) {
			defer c.Close()
			buf := make([]byte, 32)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			c.Write(buf[:n])
		}
	}
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port != 80 {
			return nil
		}
		return func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 32)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			c.Write(buf[:n])
		}
	}
	s.OnUDPForward = func(dst netip.AddrPort) func(tailcat.ConnPacketConn) {
		if dst != backendAddr {
			return nil
		}
		return func(c tailcat.ConnPacketConn) {
			upstream, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
			if err != nil {
				c.Close()
				return
			}
			tailcat.ProxyPacketConns(c, upstream)
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	cl := &tailcat.Client{Server: s.TailcatAddr(), Logf: testLogger(t, "client")}
	t.Cleanup(func() { cl.Close() })
	pingUntilDirect(t, cl)
	clientForAddr := func(tailcat.Addr) *tailcat.Client { return cl }

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("udp_to_server", func(t *testing.T) {
		c, err := dialSOCKSTarget(ctx, "udp", socksTarget{toServer: true, port: 53}, cl, clientForAddr)
		if err != nil {
			t.Fatalf("dial udp to server: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("udp-server")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read udp echo: %v", err)
		}
		if got := string(buf[:n]); got != "udp-server" {
			t.Fatalf("udp echo = %q; want %q", got, "udp-server")
		}
	})

	t.Run("udp_addr", func(t *testing.T) {
		c, err := dialSOCKSTarget(ctx, "udp", socksTarget{addr: s.TailcatAddr(), port: 53}, cl, clientForAddr)
		if err != nil {
			t.Fatalf("dial udp to addr: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("udp-blob")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read udp echo: %v", err)
		}
		if got := string(buf[:n]); got != "udp-blob" {
			t.Fatalf("udp echo = %q; want %q", got, "udp-blob")
		}
	})

	t.Run("udp_exit_node", func(t *testing.T) {
		c, err := dialSOCKSTarget(ctx, "udp", socksTarget{dst: backendAddr}, cl, clientForAddr)
		if err != nil {
			t.Fatalf("dial udp exit node: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("udp-exit")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read udp echo: %v", err)
		}
		if got := string(buf[:n]); got != "udp-exit" {
			t.Fatalf("udp echo = %q; want %q", got, "udp-exit")
		}
	})

	t.Run("tcp_to_server", func(t *testing.T) {
		c, err := dialSOCKSTarget(ctx, "tcp", socksTarget{toServer: true, port: 80}, cl, clientForAddr)
		if err != nil {
			t.Fatalf("dial tcp to server: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("tcp-server")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read tcp echo: %v", err)
		}
		if got := string(buf[:n]); got != "tcp-server" {
			t.Fatalf("tcp echo = %q; want %q", got, "tcp-server")
		}
	})

	t.Run("udp_no_client", func(t *testing.T) {
		if _, err := dialSOCKSTarget(ctx, "udp", socksTarget{toServer: true, port: 53}, nil, clientForAddr); err == nil {
			t.Fatal("dial udp without client succeeded; want error")
		}
	})
}

// TestSOCKSUDPAssociateEndToEnd speaks raw SOCKS5 (greeting + UDP ASSOCIATE)
// to a real socks5.Server wired with the tailcat dialer and exchanges a
// datagram with the tailcat server through the UDP relay. This proves the
// full wire path, not just the dialer: relay framing, target-conn caching,
// and the netstack packet conn behind it.
func TestSOCKSUDPAssociateEndToEnd(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, testLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	s := &tailcat.Server{Logf: testLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnUDP = func(port uint16) func(tailcat.ConnPacketConn) {
		if port != 53 {
			return nil
		}
		return func(c tailcat.ConnPacketConn) {
			defer c.Close()
			buf := make([]byte, 2048)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			c.Write(buf[:n])
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	cl := &tailcat.Client{Server: s.TailcatAddr(), Logf: testLogger(t, "client")}
	t.Cleanup(func() { cl.Close() })
	pingUntilDirect(t, cl)
	clientForAddr := func(tailcat.Addr) *tailcat.Client { return cl }

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socksLn.Close() })
	ss := &socks5.Server{
		Logf: testLogger(t, "socks5"),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dst, err := classifySOCKSAddr(ctx, lookupNetIP, addr)
			if err != nil {
				return nil, err
			}
			return dialSOCKSTarget(ctx, network, dst, cl, clientForAddr)
		},
	}
	go func() { _ = ss.Serve(socksLn) }()

	tcp, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if err := tcp.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Greeting: version 5, one method, no auth.
	if _, err := tcp.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(tcp, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("socks greeting reply = %v; want [5 0]", greet)
	}

	// UDP ASSOCIATE with a wildcard expected source.
	if _, err := tcp.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	relayAddr := readSOCKSReply(t, tcp)

	// One datagram to server.tailcat:53 through the relay; the tailcat
	// server echoes it back through the same association.
	const payload = "socks-udp-e2e"
	req := buildSOCKSUDP(wireDomain("server.tailcat", 53), []byte(payload))
	udp, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2048)
	n, err := udp.Read(resp)
	if err != nil {
		t.Fatalf("read relayed udp echo: %v", err)
	}
	if got := string(parseSOCKSUDP(t, resp[:n])); got != payload {
		t.Fatalf("relayed udp echo = %q; want %q", got, payload)
	}
}

// readSOCKSReply reads a SOCKS5 command reply and returns the bound address.
func readSOCKSReply(t *testing.T, r io.Reader) *net.UDPAddr {
	t.Helper()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		t.Fatalf("socks reply = %v; want version 5, success", hdr)
	}
	var ip net.IP
	switch hdr[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			t.Fatal(err)
		}
		ip = net.IP(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			t.Fatal(err)
		}
		ip = net.IP(b)
	default:
		t.Fatalf("unexpected reply address type %#x", hdr[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		t.Fatal(err)
	}
	return &net.UDPAddr{IP: ip, Port: int(pb[0])<<8 | int(pb[1])}
}

// wireDomain encodes a domain destination for a SOCKS UDP header.
func wireDomain(host string, port uint16) []byte {
	b := []byte{0x03, byte(len(host))}
	b = append(b, host...)
	return append(b, byte(port>>8), byte(port))
}

// buildSOCKSUDP frames a payload in a SOCKS UDP request header.
func buildSOCKSUDP(dst, payload []byte) []byte {
	pkt := []byte{0x00, 0x00, 0x00}
	pkt = append(pkt, dst...)
	return append(pkt, payload...)
}

// parseSOCKSUDP strips the SOCKS UDP response header, returning the payload.
func parseSOCKSUDP(t *testing.T, pkt []byte) []byte {
	t.Helper()
	if len(pkt) < 4 || pkt[0] != 0 || pkt[1] != 0 {
		t.Fatalf("bad udp response header %v", pkt)
	}
	rest := pkt[3:]
	var hlen int
	switch rest[0] {
	case 0x01:
		hlen = 1 + 4 + 2
	case 0x04:
		hlen = 1 + 16 + 2
	case 0x03:
		if len(rest) < 2 {
			t.Fatalf("short domain udp response %v", pkt)
		}
		hlen = 1 + 1 + int(rest[1]) + 2
	default:
		t.Fatalf("unexpected udp response address type %#x", rest[0])
	}
	if len(rest) < hlen {
		t.Fatalf("truncated udp response %v", pkt)
	}
	return rest[hlen:]
}

func testLogger(t *testing.T, name string) logger.Logf {
	t.Helper()
	return func(format string, args ...any) {
		t.Logf("["+name+"] "+format, args...)
	}
}

// pingUntilDirect polls Ping until the tunnel is up, like the library's
// PingForTest helper (which lives in the tailcat package's own tests and
// can't be imported here).
func pingUntilDirect(t *testing.T, cl *tailcat.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if _, err := cl.Ping(ctx); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for ping: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
