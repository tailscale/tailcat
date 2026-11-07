// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/logger"
)

// socksRemoteDNSTimeout bounds each DNS server's lookup when the socks
// subcommand resolves hostnames through the exit node (its --dns flag),
// so an unreachable or unresponsive server still leaves time in the
// SOCKS dial budget to fall back to the next one.
const socksRemoteDNSTimeout = 4 * time.Second

// parseSOCKSDNSFlag parses and validates the socks subcommand's --dns
// flag. An empty flag returns no servers, meaning hostnames resolve
// locally. The servers are reached through the exit node, so a
// non-empty flag requires the exit node's address, addr.
func parseSOCKSDNSFlag(dnsFlag string, addr tailcat.Addr) ([]netip.AddrPort, error) {
	if dnsFlag == "" {
		return nil, nil
	}
	servers, err := parseDNSServers(dnsFlag)
	if err != nil {
		return nil, fmt.Errorf("--dns: %w", err)
	}
	if addr == "" {
		return nil, errors.New("--dns requires a <tc-addr> argument naming the exit node to resolve through")
	}
	return servers, nil
}

// parseDNSServers parses a comma-separated list of DNS server IP
// addresses, each with an optional port (53 if omitted). An IPv6
// address with a port is written in brackets, as in "[2001:db8::1]:53".
func parseDNSServers(s string) ([]netip.AddrPort, error) {
	var servers []netip.AddrPort
	for f := range strings.SplitSeq(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(f)
		if err != nil {
			ip, ipErr := netip.ParseAddr(f)
			if ipErr != nil {
				return nil, fmt.Errorf("invalid DNS server %q; want an IP address with an optional :port", f)
			}
			ap = netip.AddrPortFrom(ip, 53)
		}
		if ap.Addr().Zone() != "" {
			return nil, fmt.Errorf("invalid DNS server %q; IPv6 zones aren't supported", f)
		}
		if ap.Port() == 0 {
			return nil, fmt.Errorf("invalid DNS server %q; port 0", f)
		}
		servers = append(servers, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	if len(servers) == 0 {
		return nil, errors.New("no DNS servers listed")
	}
	return servers, nil
}

// remoteLookupNetIP returns a lookup func for [classifySOCKSAddr] that
// resolves hostnames with DNS queries sent over TCP connections opened
// with dial, which the socks subcommand points at the exit node
// ([tailcat.Client.DialTCP]). Names thus resolve as they do on the exit
// node's network rather than the local one.
//
// The servers are tried in order, each for at most perServerTimeout,
// moving on to the next when one can't be reached or fails to answer.
// A definitive answer that the name doesn't exist is returned without
// asking the rest, so list servers that know private names first.
//
// As with Go's resolver generally, the local hosts file is consulted
// before any server, and the local resolver configuration's search
// domains and options still apply; only the servers queried change.
// The localhost names reserved by RFC 6761 resolve to loopback without
// a query, as they do with the local resolver, even on Windows, whose
// hosts file omits them (see package localhostdns).
func remoteLookupNetIP(logf logger.Logf, dial func(context.Context, netip.AddrPort) (net.Conn, error), servers []netip.AddrPort, perServerTimeout time.Duration) func(context.Context, string) ([]netip.Addr, error) {
	resolvers := make([]*net.Resolver, len(servers))
	for i, server := range servers {
		resolvers[i] = &net.Resolver{
			PreferGo: true,
			// Dial ignores the server address the local resolver
			// configuration chose and connects to server instead.
			// The returned conn is not a net.PacketConn, so per the
			// net.Resolver.Dial contract the resolver uses DNS over
			// TCP framing on it, even for queries it would have sent
			// over UDP.
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dial(ctx, server)
			},
		}
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		if isLocalhostName(host) {
			return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}, nil
		}
		var errs []error
		for i, r := range resolvers {
			lookupCtx, cancel := context.WithTimeout(ctx, perServerTimeout)
			ips, err := r.LookupNetIP(lookupCtx, "ip", host)
			cancel()
			if err == nil {
				return ips, nil
			}
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				// Name the server actually queried, not the one
				// from the local configuration that Dial ignored.
				dnsErr.Server = servers[i].String()
				if dnsErr.IsNotFound {
					return nil, err
				}
			}
			logf("socks: remote DNS server %v: %v", servers[i], err)
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errors.Join(errs...)
	}
}

// isLocalhostName reports whether host is "localhost" or a name ending
// in ".localhost", the names RFC 6761 reserves to mean loopback.
func isLocalhostName(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
