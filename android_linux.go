// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

// The static linux binaries are commonly run as raw executables on
// Android, under Termux, adb shell, or a rooted shell, where a plain
// Go binary is nearly useless: there is no /etc/resolv.conf, so every
// DNS lookup fails; Go's linux root loader finds no CA certificates,
// so every TLS handshake fails; and app UIDs may not enumerate
// network interfaces, so netmon cannot start. These two packages fix
// all three at init by talking to Android's DNS resolver daemon,
// pointing the root loader at the system certificate store, and
// registering a synthetic single-interface fallback. Both detect
// Android at runtime and do nothing on regular Linux. See
// https://github.com/tailscale/tailcat/issues/117.
import (
	_ "tailscale.com/feature/androidbin"
	_ "tailscale.com/feature/androiddns"
)
