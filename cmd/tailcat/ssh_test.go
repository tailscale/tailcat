// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"strings"
	"testing"

	"github.com/tailscale/tailcat"
)

func TestSSHProxyCommandDERPMap(t *testing.T) {
	const (
		exe  = "/path/to/tailcat"
		key  = "client-default"
		blob = "tc-short-blob"
		port = "22"
		url  = "https://derp.example.com/derpmap.json"
	)

	got := sshProxyCommand(exe, key, url, blob, port)
	want := exe + ` --key="client-default" --derpmap-url="https://derp.example.com/derpmap.json" tc-short-blob 22`
	if got != want {
		t.Errorf("sshProxyCommand with custom DERP map = %q; want %q", got, want)
	}

	got = sshProxyCommand(exe, key, tailcat.DefaultDERPMapURL, blob, port)
	want = exe + ` --key="client-default" tc-short-blob 22`
	if got != want {
		t.Errorf("sshProxyCommand with default DERP map = %q; want %q", got, want)
	}
}

func TestSSHDestHost(t *testing.T) {
	// A realistic ConnBlob, taken from an existing test fixture elsewhere
	// in this package.
	const blob = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"

	got := sshDestHost(blob)
	if !strings.HasPrefix(got, "tailcat-") {
		t.Fatalf("sshDestHost(%q) = %q; want tailcat- prefix", blob, got)
	}
	if len(got) > 24 {
		t.Fatalf("sshDestHost(%q) = %q (%d bytes); want a short, fixed-width host", blob, got, len(got))
	}

	// Deterministic: same blob always produces the same host, so ssh's own
	// connection sharing (keyed off ControlPath, hence off this string)
	// keeps reusing the right control socket across invocations.
	if again := sshDestHost(blob); again != got {
		t.Fatalf("sshDestHost(%q) is not deterministic: %q != %q", blob, got, again)
	}

	// Distinct blobs must not collide, or ssh would multiplex two different
	// tailcat servers onto the same control socket.
	const otherBlob = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGF2"
	if other := sshDestHost(otherBlob); other == got {
		t.Fatalf("sshDestHost collided for distinct blobs: %q", got)
	}

	// The whole point: it must actually fit an AF_UNIX ControlPath, unlike
	// a long ConnBlob used directly. Linux's sun_path is 108 bytes,
	// including the trailing NUL; macOS's is 104. Give plenty of headroom
	// for a real home directory and username.
	const controlPath = "/home/someuser/.ssh/master-someuser@" + "PLACEHOLDER" + ":22"
	if got := len(strings.Replace(controlPath, "PLACEHOLDER", sshDestHost(blob), 1)); got >= 100 {
		t.Fatalf("example ControlPath is %d bytes; want comfortably under the ~104-108 byte AF_UNIX limit", got)
	}
}
