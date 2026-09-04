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

// baseTags are non-feature build tags included in every tailcat
// build: osusergo and netgo select the pure Go user and DNS resolver
// implementations, and omitidna and omitpemdecrypt drop unused code
// from tailscale.com dependencies.
var baseTags = []string{"osusergo", "netgo", "omitidna", "omitpemdecrypt"}

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
// throughput loss), and bakedroots (embedded LetsEncrypt roots as a
// TLS fallback, so DERP connections still verify on machines with a
// missing or broken system CA store; about 4 KB). The wasm build
// needs no roots because the browser does its own TLS. Note that
// featuretags.Requires pulls in ssh's c2n and dbus dependencies too.
var releaseKeep = []featuretags.FeatureTag{
	"netstack",
	"ssh",
	"gro",
	"bakedroots",
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
	tags := slices.Clone(baseTags)
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
