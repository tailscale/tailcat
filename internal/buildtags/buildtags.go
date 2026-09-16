// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package buildtags computes the go build tag lists that tailcat
// binaries are built with. Starting from a small allowlist of
// tailscale.com features that tailcat needs, expanded with their
// dependencies via featuretags.Requires, every other omittable
// feature in the featuretags registry is excluded with its ts_omit_
// build tag.
package buildtags

import (
	"slices"
	"strings"

	"tailscale.com/feature/featuretags"
)

// The tag lists are purely ts_omit_ feature tags. They deliberately
// exclude some non-feature tags used in the past: netgo and osusergo
// are redundant with the CGO_ENABLED=0 official builds already use
// for static binaries, and netgo additionally forces Go's pure DNS
// resolver on Windows and macOS, which broke resolving "localhost" on
// Windows (issue #108). omitidna and omitpemdecrypt only ever meant
// something to the tailscale/go fork toolchain, not the stock Go
// toolchain tailcat builds with.

// wasmKeep is the set of tailscale.com feature tags the wasm build
// needs linked, following cmd/tsconnect/wasmbuild. tailcat uses the
// data plane only, so it needs little: netstack for userspace TCP
// (wasm has no kernel TUN) and nothing else. Omitting the rest
// shrinks the wasm binary by about 6 MB (18%).
var wasmKeep = []featuretags.FeatureTag{
	"netstack",
}

// releaseKeep is the set of tailscale.com feature tags native builds
// of cmd/tailcat need linked: wasmKeep plus ssh (the ssh subcommand
// and the SSH services are compiled out under ts_omit_ssh),
// gro (omitting it disables GRO/GSO in netstack on Linux, a pure
// throughput loss), bakedroots (embedded LetsEncrypt roots as a
// TLS fallback, so DERP connections still verify on machines with a
// missing or broken system CA store; about 4 KB), and androidbin
// (which pulls in androiddns), so the static linux binaries work
// when run as raw executables on Android under Termux, adb, or a
// rooted shell, where a plain Go binary has no working DNS, no CA
// roots, and no interface enumeration; those packages detect Android
// at runtime and are inert elsewhere. The wasm build needs no roots
// because the browser does its own TLS. Note that
// featuretags.Requires pulls in ssh's c2n and dbus dependencies too.
var releaseKeep = []featuretags.FeatureTag{
	"netstack",
	"ssh",
	"gro",
	"bakedroots",
	"androidbin",
}

// WasmTags returns the comma-joined -tags value for the wasm build,
// sorted so the same source tree always produces the same wasm bytes.
func WasmTags() string {
	return tags(wasmKeep)
}

// ReleaseTags returns the comma-joined -tags value for native builds
// of cmd/tailcat. It must match the checked-in build-tags.txt file
// and the -tags= line in .goreleaser.yaml; a test enforces both.
func ReleaseTags() string {
	return tags(releaseKeep)
}

func tags(keep []featuretags.FeatureTag) string {
	keepSet := map[featuretags.FeatureTag]bool{}
	for _, ft := range keep {
		for dep := range featuretags.Requires(ft) {
			keepSet[dep] = true
		}
	}
	var tags []string
	for ft := range featuretags.Features {
		if ft == "" || !ft.IsOmittable() {
			continue
		}
		if !keepSet[ft] {
			tags = append(tags, ft.OmitTag())
		}
	}
	slices.Sort(tags)
	return strings.Join(tags, ",")
}
