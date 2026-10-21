// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

// The port mapper asks the local router for a public UDP port mapping
// (UPnP IGD, NAT-PMP, or PCP) and adds it to the endpoints magicsock
// advertises. Without it, a peer behind a NAT that allocates a new
// public port per destination (a "hard" NAT, common on hotel, office,
// and carrier networks) can reach a peer behind an ordinary home
// router only over DERP: neither side's STUN-learned endpoint is
// reachable from the other, so hole punching fails. With a mapping,
// the home side has an endpoint that accepts packets from any source,
// and the path goes direct.
//
// magicsock only creates a port mapper when this package registers
// one; it doesn't need to be linked by any other path. The import is
// a no-op under the ts_omit_portmapper build tag, which the wasm build
// sets: a browser has no UDP sockets, so it has nothing to map.
import _ "tailscale.com/feature/condregister/portmapper"
