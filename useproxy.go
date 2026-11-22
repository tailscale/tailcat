// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

// Some sandboxes, such as ChatGPT Work's, reach the internet only through
// an HTTP proxy. This package makes DERP connections use the proxy named by
// HTTPS_PROXY (or the OS proxy settings, on Windows) via HTTP CONNECT. See
// https://github.com/tailscale/tailscale/issues/22412.
import _ "tailscale.com/feature/useproxy"
