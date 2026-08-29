// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
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
			name:   "blob_host",
			addr:   "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu:8081",
			lookup: noLookup,
			want: socksTarget{
				blob: "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu",
				port: 8081,
			},
		},
		{
			name:   "tc_prefixed_non_blob_host_uses_lookup",
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
			name:  "omit address",
			input: ":1234",
			want:  "0.0.0.0:1234",
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
				t.Fatalf("classifyListenAddrPort(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}
