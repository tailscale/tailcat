// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localhostdns

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

// The tests use a subdomain of localhost rather than "localhost"
// itself: hosts files never contain subdomains of localhost, so the
// lookups are guaranteed to reach this package's fake DNS server
// rather than being answered from /etc/hosts, on Windows and Linux
// alike.

func TestLookupLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, name := range []string{"sub.localhost", "SUB.LOCALHOST", "deep.sub.localhost"} {
		addrs, err := Resolver.LookupIPAddr(ctx, name)
		if err != nil {
			t.Fatalf("LookupIPAddr(%q): %v", name, err)
		}
		var v4, v6 bool
		for _, a := range addrs {
			if a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				v4 = true
			}
			if a.IP.Equal(net.IPv6loopback) {
				v6 = true
			}
			if !a.IP.IsLoopback() {
				t.Errorf("LookupIPAddr(%q) returned non-loopback %v", name, a.IP)
			}
		}
		if !v4 || !v6 {
			t.Errorf("LookupIPAddr(%q) = %v; want both 127.0.0.1 and ::1", name, addrs)
		}
	}
}

func TestLookupOtherNXDOMAIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The .invalid TLD can never exist, so even a bug that forwarded
	// this query to real DNS servers would get the same answer.
	_, err := Resolver.LookupIPAddr(ctx, "tailcat-test.invalid")
	if err == nil {
		t.Fatal("LookupIPAddr of non-localhost name unexpectedly succeeded")
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("LookupIPAddr error = %v; want a not-found DNSError", err)
	}
}

// TestDialFallback is the regression test for tailcat issue #108's
// two failure modes: resolving localhost at all, and reaching a
// service bound to only one of the two loopback addresses.
func TestDialFallback(t *testing.T) {
	for _, listenAddr := range []string{"127.0.0.1:0", "[::1]:0"} {
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			t.Logf("skipping %v: %v", listenAddr, err)
			continue
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("hi"))
				c.Close()
			}
		}()

		port := ln.Addr().(*net.TCPAddr).Port
		d := &net.Dialer{Resolver: Resolver, Timeout: 5 * time.Second}
		c, err := d.Dial("tcp", net.JoinHostPort("sub.localhost", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("dial sub.localhost against %v listener: %v", listenAddr, err)
		}
		buf := make([]byte, 2)
		if _, err := c.Read(buf); err != nil || string(buf) != "hi" {
			t.Fatalf("read from %v listener: %q, %v", listenAddr, buf, err)
		}
		c.Close()
	}
}
