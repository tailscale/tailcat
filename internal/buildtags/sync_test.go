// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package buildtags

import (
	"os"
	"strings"
	"testing"
)

// skipIfTailscaleCI skips the test when running in the
// tailscale/tailscale repo's CI. That repo's tailcat.yml workflow
// tests tailcat against tailscale.com at head, rather than the
// release pinned in go.mod, as an early warning that a change there
// breaks tailcat. The checked-in artifacts this test verifies are
// generated from the pinned release, so any change to the feature
// registry at head would fail this test spuriously. That workflow
// only cares that tailcat still compiles and its basics work.
func skipIfTailscaleCI(t *testing.T) {
	if os.Getenv("GITHUB_REPOSITORY") == "tailscale/tailscale" {
		t.Skip("skipping in tailscale/tailscale CI, which tests against tailscale.com at head")
	}
}

// TestReleaseTagsInSync asserts that the checked-in build-tags.txt
// file (the entrypoint for third-party packagers) and the -tags= line
// in .goreleaser.yaml both carry exactly the tags ReleaseTags
// returns. It reads the yaml as plain text on purpose: the repo has
// no YAML dependency and an exact substring match is all that is
// needed. Regenerate both with: go run ./internal/buildtags/printtags
func TestReleaseTagsInSync(t *testing.T) {
	skipIfTailscaleCI(t)
	const regen = "regenerate with: go run ./internal/buildtags/printtags"

	txt, err := os.ReadFile("../../build-tags.txt")
	if err != nil {
		t.Fatal(err)
	}
	// A .gitattributes rule keeps the file LF, but clones that predate
	// the rule on a core.autocrlf=true checkout can still see CRLF, so
	// normalize before comparing.
	got := strings.ReplaceAll(string(txt), "\r\n", "\n")
	if want := ReleaseTags() + "\n"; got != want {
		t.Errorf("build-tags.txt content is stale; %s\n got: %s\nwant: %s", regen, got, want)
	}

	yml, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if want := "-tags=" + ReleaseTags(); !strings.Contains(string(yml), want) {
		t.Errorf(".goreleaser.yaml does not contain %q; %s", want, regen)
	}
	if n := strings.Count(string(yml), "-tags="); n != 1 {
		t.Errorf(".goreleaser.yaml contains %d \"-tags=\" occurrences; want exactly 1", n)
	}
}
