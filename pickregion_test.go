// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package tailcat

import (
	"context"
	"testing"
	"testing/synctest"

	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/nettype"
)

// TestPickBestRegionClosesSockets checks that PickBestRegion doesn't
// leave its netcheck STUN sockets open after it returns, even when
// the caller's context never ends. Previously they stayed open (with
// a goroutine each) for the life of the caller's context, which for
// "tailcat serve" was the life of the process.
func TestPickBestRegionClosesSockets(t *testing.T) {
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(stunCleanup)

	dm := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{{
					Name:       "t1",
					RegionID:   1,
					HostName:   "127.0.0.1",
					IPv4:       "127.0.0.1",
					IPv6:       "none",
					STUNPort:   stunAddr.Port,
					STUNTestIP: "127.0.0.1",
				}},
			},
		},
	}

	// synctest.Test fails if any goroutine started in the bubble
	// outlives it, which catches leaked STUN reader goroutines.
	synctest.Test(t, func(t *testing.T) {
		got, err := PickBestRegion(context.Background(), dm)
		if err != nil {
			t.Fatalf("PickBestRegion: %v", err)
		}
		if got != 1 {
			t.Errorf("PickBestRegion = %v; want 1", got)
		}
	})
}
