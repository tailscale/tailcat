// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package localhostdns provides a net.Resolver that resolves
// "localhost" itself instead of trusting the operating system to.
//
// Go's pure resolver, used by any binary built with the netgo build
// tag (or run with GODEBUG=netdns=go), resolves "localhost" from the
// hosts file. Windows ships its hosts file with the localhost entries
// commented out ("localhost name resolution is handled within DNS
// itself"), expecting resolvers to special-case the name. Go's
// resolver does not (a fix is pending in
// https://go-review.googlesource.com/c/go/+/831864), so on Windows
// the query escapes to real DNS servers, which don't know the name,
// and dialing "localhost" fails. Official tailcat binaries no longer
// build with netgo, but packagers and GODEBUG can still select the
// pure resolver, so dialing through this resolver keeps localhost
// meaning loopback regardless. See
// https://github.com/tailscale/tailcat/issues/108.
//
// [Resolver] answers "localhost" and any name ending in ".localhost"
// (the names RFC 6761 reserves to mean loopback) with both 127.0.0.1
// and ::1, so a net.Dialer using it tries one loopback address and
// falls back to the other as usual for a dual-stack name. It answers
// every other DNS query with NXDOMAIN rather than forwarding to real
// DNS servers, making it usable only by dialers that dial loopback
// names, IP literals, and hosts-file names. That non-forwarding is
// also what makes it safe: a search domain from DHCP can expand
// "localhost" to a query like "localhost.lan" that a creative
// gateway might answer with a non-loopback address, and here that
// query gets NXDOMAIN like any other.
package localhostdns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Resolver resolves localhost names to the loopback addresses without
// consulting real DNS servers, as described in the package comment.
// The hosts file still applies: Go's resolver consults it before
// asking any DNS server, including this fake one.
var Resolver = &net.Resolver{
	PreferGo: true,
	Dial:     dialFakeServer,
}

// dialFakeServer is the [net.Resolver.Dial] hook. It ignores the DNS
// server address the system configuration chose and returns a pipe to
// an in-process DNS server instead. The returned conn is not a
// net.PacketConn, so per the net.Resolver.Dial contract the resolver
// speaks TCP framing (two-byte length prefixes) over it even when it
// wanted UDP.
func dialFakeServer(ctx context.Context, network, address string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	go serve(serverConn)
	return clientConn, nil
}

// serve answers TCP-framed DNS queries on c until c fails, typically
// because the resolver closed its end after its lookup.
func serve(c net.Conn) {
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
		resp, err := answer(query)
		if err != nil {
			return
		}
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

// answer builds the TCP-framed DNS response to the query: loopback
// addresses for localhost names, NXDOMAIN for everything else.
func answer(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	qh, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	h := dnsmessage.Header{
		ID:            qh.ID,
		Response:      true,
		Authoritative: true,
	}
	if !isLocalhost(q.Name) {
		h.RCode = dnsmessage.RCodeNameError
	}

	// The first two bytes of the buffer become the length prefix
	// after Finish, once the message length is known.
	b := dnsmessage.NewBuilder(make([]byte, 2, 128), h)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if h.RCode == dnsmessage.RCodeSuccess {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		rh := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Class: dnsmessage.ClassINET,
			TTL:   600,
		}
		switch q.Type {
		case dnsmessage.TypeA:
			if err := b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}); err != nil {
				return nil, err
			}
		case dnsmessage.TypeAAAA:
			var ip6Loopback [16]byte
			ip6Loopback[15] = 1
			if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ip6Loopback}); err != nil {
				return nil, err
			}
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(msg, uint16(len(msg)-2))
	return msg, nil
}

// isLocalhost reports whether the absolute, possibly mixed-case DNS
// name is "localhost" or a subdomain of it.
func isLocalhost(name dnsmessage.Name) bool {
	n := strings.ToLower(name.String())
	return n == "localhost." || strings.HasSuffix(n, ".localhost.")
}
