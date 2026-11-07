// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tstest/integration"
)

func TestParseDNSServers(t *testing.T) {
	ap := netip.MustParseAddrPort
	tests := []struct {
		in      string
		want    []netip.AddrPort
		wantErr string
	}{
		{in: "1.1.1.1", want: []netip.AddrPort{ap("1.1.1.1:53")}},
		{in: "1.1.1.1:5353", want: []netip.AddrPort{ap("1.1.1.1:5353")}},
		{in: " 10.0.0.53 , 8.8.8.8:53 ,", want: []netip.AddrPort{ap("10.0.0.53:53"), ap("8.8.8.8:53")}},
		{in: "2001:db8::1", want: []netip.AddrPort{ap("[2001:db8::1]:53")}},
		{in: "[2001:db8::1]:5353", want: []netip.AddrPort{ap("[2001:db8::1]:5353")}},
		{in: "::ffff:192.0.2.1", want: []netip.AddrPort{ap("192.0.2.1:53")}},
		{in: "dns.example", wantErr: "invalid DNS server"},
		{in: "1.1.1.1:dns", wantErr: "invalid DNS server"},
		{in: "1.1.1.1:0", wantErr: "port 0"},
		{in: "fe80::1%eth0", wantErr: "zones"},
		{in: "", wantErr: "no DNS servers"},
		{in: " , ", wantErr: "no DNS servers"},
	}
	for _, tt := range tests {
		got, err := parseDNSServers(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseDNSServers(%q) = %v, %v; want error containing %q", tt.in, got, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDNSServers(%q): %v", tt.in, err)
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("parseDNSServers(%q) = %v; want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseSOCKSDNSFlag(t *testing.T) {
	const exitNode = tailcat.Addr("tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu")

	// Unset means local resolution, with or without an exit node.
	for _, addr := range []tailcat.Addr{"", exitNode} {
		if got, err := parseSOCKSDNSFlag("", addr); got != nil || err != nil {
			t.Errorf("parseSOCKSDNSFlag(\"\", %q) = %v, %v; want nil, nil", addr, got, err)
		}
	}
	if got, err := parseSOCKSDNSFlag("10.0.0.53,1.1.1.1", exitNode); err != nil || len(got) != 2 {
		t.Errorf("parseSOCKSDNSFlag with exit node = %v, %v; want two servers", got, err)
	}
	if _, err := parseSOCKSDNSFlag("10.0.0.53", ""); err == nil || !strings.Contains(err.Error(), "<tc-addr>") {
		t.Errorf("parseSOCKSDNSFlag without exit node: err = %v; want one asking for <tc-addr>", err)
	}
	if _, err := parseSOCKSDNSFlag("dns.example", exitNode); err == nil || !strings.HasPrefix(err.Error(), "--dns: ") {
		t.Errorf("parseSOCKSDNSFlag(bad server): err = %v; want a --dns error", err)
	}
}

// socksDNSFlagValue returns the parsed value of the socks subcommand's
// --dns flag.
func socksDNSFlagValue(t *testing.T, root *ff.Command) string {
	t.Helper()
	for _, sub := range root.Subcommands {
		if sub.Name != "socks" {
			continue
		}
		f, ok := sub.Flags.GetFlag("dns")
		if !ok {
			t.Fatal("socks has no --dns flag")
		}
		return f.GetValue()
	}
	t.Fatal("no socks subcommand")
	return ""
}

func TestSOCKSDNSFlag(t *testing.T) {
	t.Setenv("TAILCAT_SOCKS_DNS", "")
	root, err := parseCLI(t, "socks")
	if err != nil {
		t.Fatal(err)
	}
	if got := socksDNSFlagValue(t, root); got != "" {
		t.Errorf("--dns default = %q; want empty (local resolution)", got)
	}

	t.Setenv("TAILCAT_SOCKS_DNS", "10.0.0.53")
	root, err = parseCLI(t, "socks")
	if err != nil {
		t.Fatal(err)
	}
	if got := socksDNSFlagValue(t, root); got != "10.0.0.53" {
		t.Errorf("--dns default with TAILCAT_SOCKS_DNS set = %q; want 10.0.0.53", got)
	}
	root, err = parseCLI(t, "socks", "--dns=1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := socksDNSFlagValue(t, root); got != "1.1.1.1" {
		t.Errorf("--dns=1.1.1.1 with TAILCAT_SOCKS_DNS set = %q; want the flag to win", got)
	}

	// Bad --dns values are usage errors, reported before anything
	// connects.
	for _, args := range [][]string{
		{"socks", "--dns=1.1.1.1"},
		{"socks", "--dns=dns.example", "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"},
	} {
		root, err := parseCLI(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		err = root.Run(t.Context())
		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("%q: err = %v; want a usageError", args, err)
		}
	}
}

// fakeDNSBehavior is how a fake DNS server in the tests below responds.
type fakeDNSBehavior int

const (
	dnsAnswer   fakeDNSBehavior = iota // answer A and AAAA queries
	dnsDown                            // fail to connect
	dnsHang                            // accept the connection but never answer
	dnsServFail                        // answer SERVFAIL
	dnsNXDomain                        // answer NXDOMAIN
)

// serveFakeDNS answers TCP-framed DNS queries on c per behavior until
// c fails. Answers give every name the A record a4 and AAAA record a6.
func serveFakeDNS(c net.Conn, behavior fakeDNSBehavior, a4, a6 netip.Addr) {
	defer c.Close()
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		if behavior == dnsHang {
			continue
		}
		var p dnsmessage.Parser
		h, err := p.Start(query)
		if err != nil {
			return
		}
		q, err := p.Question()
		if err != nil {
			return
		}
		rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
		switch behavior {
		case dnsServFail:
			rh.RCode = dnsmessage.RCodeServerFailure
		case dnsNXDomain:
			rh.RCode = dnsmessage.RCodeNameError
		}
		b := dnsmessage.NewBuilder(make([]byte, 2, 514), rh)
		b.EnableCompression()
		if err := b.StartQuestions(); err != nil {
			return
		}
		if err := b.Question(q); err != nil {
			return
		}
		if err := b.StartAnswers(); err != nil {
			return
		}
		if behavior == dnsAnswer {
			rrh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			switch q.Type {
			case dnsmessage.TypeA:
				err = b.AResource(rrh, dnsmessage.AResource{A: a4.As4()})
			case dnsmessage.TypeAAAA:
				err = b.AAAAResource(rrh, dnsmessage.AAAAResource{AAAA: a6.As16()})
			}
			if err != nil {
				return
			}
		}
		resp, err := b.Finish()
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(resp, uint16(len(resp)-2))
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

func TestRemoteLookupNetIP(t *testing.T) {
	var (
		first  = netip.MustParseAddrPort("192.0.2.1:53")
		second = netip.MustParseAddrPort("192.0.2.2:53")
		a4     = netip.MustParseAddr("10.1.2.3")
		a6     = netip.MustParseAddr("fd00::1:2:3")
	)
	// The test names are rooted so the local resolver configuration's
	// search domains don't add queries.
	const host = "intranet.tailcat.test."

	tests := []struct {
		name         string
		behaviors    map[netip.AddrPort]fakeDNSBehavior
		host         string
		want         []netip.Addr
		wantErr      bool
		wantNotFound bool
		wantDialed   []netip.AddrPort
	}{
		{
			name:       "first_answers",
			behaviors:  map[netip.AddrPort]fakeDNSBehavior{first: dnsAnswer, second: dnsAnswer},
			host:       host,
			want:       []netip.Addr{a4, a6},
			wantDialed: []netip.AddrPort{first},
		},
		{
			name:       "first_unreachable",
			behaviors:  map[netip.AddrPort]fakeDNSBehavior{first: dnsDown, second: dnsAnswer},
			host:       host,
			want:       []netip.Addr{a4, a6},
			wantDialed: []netip.AddrPort{first, second},
		},
		{
			name:       "first_hangs",
			behaviors:  map[netip.AddrPort]fakeDNSBehavior{first: dnsHang, second: dnsAnswer},
			host:       host,
			want:       []netip.Addr{a4, a6},
			wantDialed: []netip.AddrPort{first, second},
		},
		{
			name:       "first_servfail",
			behaviors:  map[netip.AddrPort]fakeDNSBehavior{first: dnsServFail, second: dnsAnswer},
			host:       host,
			want:       []netip.Addr{a4, a6},
			wantDialed: []netip.AddrPort{first, second},
		},
		{
			name:         "first_nxdomain_is_final",
			behaviors:    map[netip.AddrPort]fakeDNSBehavior{first: dnsNXDomain, second: dnsAnswer},
			host:         host,
			wantErr:      true,
			wantNotFound: true,
			wantDialed:   []netip.AddrPort{first},
		},
		{
			name:       "all_unreachable",
			behaviors:  map[netip.AddrPort]fakeDNSBehavior{first: dnsDown, second: dnsDown},
			host:       host,
			wantErr:    true,
			wantDialed: []netip.AddrPort{first, second},
		},
		{
			name:      "localhost_stays_local",
			behaviors: map[netip.AddrPort]fakeDNSBehavior{first: dnsAnswer, second: dnsAnswer},
			host:      "LocalHost",
			want:      []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()},
		},
		{
			name:      "dot_localhost_stays_local",
			behaviors: map[netip.AddrPort]fakeDNSBehavior{first: dnsAnswer, second: dnsAnswer},
			host:      "foo.localhost.",
			want:      []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var dialed []netip.AddrPort
			dial := func(ctx context.Context, server netip.AddrPort) (net.Conn, error) {
				mu.Lock()
				if !slices.Contains(dialed, server) {
					dialed = append(dialed, server)
				}
				mu.Unlock()
				behavior, ok := tt.behaviors[server]
				if !ok {
					t.Errorf("dialed unexpected DNS server %v", server)
					return nil, errors.New("unexpected server")
				}
				if behavior == dnsDown {
					return nil, errors.New("connection refused")
				}
				c, s := net.Pipe()
				go serveFakeDNS(s, behavior, a4, a6)
				return c, nil
			}
			lookup := remoteLookupNetIP(t.Logf, dial, []netip.AddrPort{first, second}, 500*time.Millisecond)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			got, err := lookup(ctx, tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("lookup(%q) = %v; want error", tt.host, got)
				}
				var dnsErr *net.DNSError
				if notFound := errors.As(err, &dnsErr) && dnsErr.IsNotFound; notFound != tt.wantNotFound {
					t.Errorf("lookup(%q) error %v: IsNotFound = %v; want %v", tt.host, err, notFound, tt.wantNotFound)
				}
				if dnsErr != nil && dnsErr.Server != first.String() {
					t.Errorf("lookup(%q) error %v: Server = %q; want the first server queried, %v", tt.host, err, dnsErr.Server, first)
				}
			} else {
				if err != nil {
					t.Fatalf("lookup(%q): %v", tt.host, err)
				}
				slices.SortFunc(got, netip.Addr.Compare)
				if !slices.Equal(got, tt.want) {
					t.Errorf("lookup(%q) = %v; want %v", tt.host, got, tt.want)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(dialed, tt.wantDialed) {
				t.Errorf("dialed DNS servers %v; want %v", dialed, tt.wantDialed)
			}
		})
	}
}

// TestSOCKSRemoteDNSThroughExitNode resolves a name with a DNS server
// that exists only on the exit node's side, reached with the client's
// DialTCP as the socks subcommand's --dns does.
func TestSOCKSRemoteDNSThroughExitNode(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, testLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	dnsServer := netip.MustParseAddrPort("192.0.2.53:53")
	want := netip.MustParseAddr("10.1.2.3")
	s := &tailcat.Server{Logf: testLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnTCPForward = func(dst netip.AddrPort) func(net.Conn) {
		if dst != dnsServer {
			return nil
		}
		return func(c net.Conn) {
			serveFakeDNS(c, dnsAnswer, want, netip.MustParseAddr("fd00::1:2:3"))
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	cl := &tailcat.Client{Server: s.TailcatAddr(), Logf: testLogger(t, "client")}
	t.Cleanup(func() { cl.Close() })
	pingUntilDirect(t, cl)

	servers, err := parseSOCKSDNSFlag(dnsServer.Addr().String(), s.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	lookup := remoteLookupNetIP(testLogger(t, "dns"), cl.DialTCP, servers, socksRemoteDNSTimeout)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	dst, err := classifySOCKSAddr(ctx, lookup, "intranet.tailcat.test.:443")
	if err != nil {
		t.Fatalf("classifySOCKSAddr: %v", err)
	}
	if wantDst := netip.AddrPortFrom(want, 443); dst != (socksTarget{dst: wantDst}) {
		t.Errorf("classifySOCKSAddr = %+v; want dst %v", dst, wantDst)
	}
}
