// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/tailcfg"
)

// Truncating a DERP region's raw node list before wireRegionOf drops STUN-only
// nodes can leave the generated address with zero relays. The genkey path must
// pick the first two nodes that can actually relay DERP traffic.
func TestFirstRelayNodesSkipsSTUNOnly(t *testing.T) {
	stun := func(name string) *tailcfg.DERPNode {
		return &tailcfg.DERPNode{Name: name, HostName: name + ".stun.example", STUNOnly: true}
	}
	relay := func(name string) *tailcfg.DERPNode {
		return &tailcfg.DERPNode{Name: name, HostName: name + ".derp.example", DERPPort: 443}
	}

	nodes := []*tailcfg.DERPNode{stun("s1"), stun("s2"), relay("d1"), relay("d2"), relay("d3")}
	got := firstRelayNodes(nodes)
	if len(got) != 2 || got[0].Name != "d1" || got[1].Name != "d2" {
		t.Fatalf("firstRelayNodes = %v; want d1, d2", nodeNames(got))
	}

	// Fewer than two relays: keep what exists, don't include STUN-only nodes.
	got = firstRelayNodes([]*tailcfg.DERPNode{stun("s1"), relay("d1")})
	if len(got) != 1 || got[0].Name != "d1" {
		t.Fatalf("firstRelayNodes = %v; want only d1", nodeNames(got))
	}
}

func nodeNames(nodes []*tailcfg.DERPNode) []string {
	var names []string
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	return names
}
