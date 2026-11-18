// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestResolveEmbedsRelayNodes checks that resolving a short address embeds
// usable DERP relay nodes. STUN-only nodes can't relay DERP traffic and are
// dropped when the address is encoded (see wireRegionOf), so truncating the
// region's raw node list before filtering them can leave a resolved address
// with fewer than two relay nodes, or none at all, breaking the promise that
// a resolved address is self-contained and works offline.
func TestResolveEmbedsRelayNodes(t *testing.T) {
	stun := func(name string) *tailcfg.DERPNode {
		return &tailcfg.DERPNode{
			Name:     name,
			HostName: name + ".stun.example",
			STUNOnly: true,
			STUNPort: 3478,
		}
	}
	relay := func(name string) *tailcfg.DERPNode {
		return &tailcfg.DERPNode{
			Name:     name,
			HostName: name + ".derp.example",
			IPv4:     "192.0.2.1",
			STUNPort: 3478,
			DERPPort: 443,
		}
	}

	tests := []struct {
		name  string
		nodes []*tailcfg.DERPNode
		want  []string
	}{
		{
			name:  "stun_only_prefix",
			nodes: []*tailcfg.DERPNode{stun("s1"), stun("s2"), relay("d1"), relay("d2"), relay("d3")},
			want:  []string{"d1.derp.example", "d2.derp.example"},
		},
		{
			name:  "interleaved_stun_only",
			nodes: []*tailcfg.DERPNode{relay("d1"), stun("s1"), relay("d2"), stun("s2"), relay("d3")},
			want:  []string{"d1.derp.example", "d2.derp.example"},
		},
		{
			name:  "three_relay_nodes",
			nodes: []*tailcfg.DERPNode{relay("d1"), relay("d2"), relay("d3")},
			want:  []string{"d1.derp.example", "d2.derp.example"},
		},
		{
			name:  "single_relay_node",
			nodes: []*tailcfg.DERPNode{stun("s1"), relay("d1")},
			want:  []string{"d1.derp.example"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv := key.NewNode()
			short := (&ConnInfo{
				ServerPublic:      NodePublic{priv.Public()},
				ServerDiscoPublic: DiscoPublicForNode(priv),
				RegionID:          1,
			}).Addr()
			dm := &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					1: {RegionID: 1, RegionCode: "tst", Nodes: tt.nodes},
				},
			}

			resolved, err := short.Resolve(context.Background(), dm)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			ci, err := ParseAddr(resolved)
			if err != nil {
				t.Fatalf("ParseAddr(resolved): %v", err)
			}
			if len(ci.Region) != 1 {
				t.Fatalf("resolved address has %d regions; want 1", len(ci.Region))
			}
			var hosts []string
			for _, n := range ci.Region[0].Nodes {
				hosts = append(hosts, n.HostName)
			}
			if diff := cmp.Diff(tt.want, hosts); diff != "" {
				t.Errorf("resolved relay nodes (-want +got):\n%s", diff)
			}
		})
	}
}
