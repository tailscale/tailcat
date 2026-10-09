// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package buildtags

import (
	"slices"
	"strings"
	"testing"
)

// tagSet splits a comma-joined tag list into a set, failing the test
// if the list is unsorted or contains duplicates.
func tagSet(t *testing.T, tags string) map[string]bool {
	t.Helper()
	list := strings.Split(tags, ",")
	if !slices.IsSorted(list) {
		t.Errorf("tag list is not sorted: %q", tags)
	}
	set := map[string]bool{}
	for _, tag := range list {
		if set[tag] {
			t.Errorf("duplicate tag %q in %q", tag, tags)
		}
		set[tag] = true
	}
	return set
}

func TestTags(t *testing.T) {
	release := tagSet(t, ReleaseTags())
	for _, want := range []string{"ts_omit_taildrop", "ts_omit_webclient"} {
		if !release[want] {
			t.Errorf("ReleaseTags missing %q", want)
		}
	}
	// See the comment in buildtags.go for why these historical
	// non-feature tags must stay gone. In particular, netgo broke
	// resolving "localhost" on Windows (issue #108).
	for _, notWant := range []string{"netgo", "osusergo", "omitidna", "omitpemdecrypt"} {
		if release[notWant] {
			t.Errorf("ReleaseTags contains %q; see the comment in buildtags.go", notWant)
		}
	}
	for _, notWant := range []string{"ts_omit_netstack", "ts_omit_ssh", "ts_omit_gro", "ts_omit_c2n", "ts_omit_dbus", "ts_omit_udptransport", "ts_omit_nattraversal"} {
		if release[notWant] {
			t.Errorf("ReleaseTags contains %q; that feature must stay linked in release builds", notWant)
		}
	}

	wasm := tagSet(t, WasmTags())
	for _, want := range []string{"ts_omit_ssh", "ts_omit_gro", "ts_omit_udptransport", "ts_omit_nattraversal"} {
		if !wasm[want] {
			t.Errorf("WasmTags missing %q", want)
		}
	}
	if wasm["ts_omit_netstack"] {
		t.Errorf("WasmTags contains ts_omit_netstack; netstack must stay linked in wasm builds")
	}
}
