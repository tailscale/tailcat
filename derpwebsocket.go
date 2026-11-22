// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

// Some sandboxes, such as ChatGPT Work's, reach the internet only through
// an HTTP proxy that intercepts TLS and refuses DERP's "Upgrade: DERP"
// request but allows WebSocket upgrades. This package makes DERP clients
// that get refused retry by speaking DERP inside WebSockets, as browsers
// do. See https://github.com/tailscale/tailscale/issues/22412.
// (On js/wasm, where DERP clients always use WebSockets, it does nothing.)
import _ "tailscale.com/feature/derpwebsocket"
