// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package buildtags

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// listDeps returns the import paths that pkg links when built for
// goos/goarch with the given tags, as reported by go list.
func listDeps(t *testing.T, goos, goarch, tags, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-tags", tags, pkg)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, stderr)
	}
	return strings.Fields(string(out))
}

// TestReleaseLinksPortMapper checks the dependency graph of the binaries
// themselves, not the test binary: tests link the port mapper on their
// own through tailscale.com/feature/condregister, so only go list shows
// whether a release build of cmd/tailcat has it. magicsock silently runs
// without a port mapper when nothing registers one.
func TestReleaseLinksPortMapper(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list")
	}
	const portmapper = "tailscale.com/feature/portmapper"
	native := listDeps(t, "linux", "amd64", ReleaseTags(), "github.com/tailscale/tailcat/cmd/tailcat")
	if !slices.Contains(native, portmapper) {
		t.Errorf("release build of cmd/tailcat does not link %s", portmapper)
	}
	wasm := listDeps(t, "js", "wasm", WasmTags(), "github.com/tailscale/tailcat/cmd/tailcat-web")
	if slices.Contains(wasm, portmapper) {
		t.Errorf("wasm build of cmd/tailcat-web links %s; a browser has no UDP sockets to map", portmapper)
	}
}
