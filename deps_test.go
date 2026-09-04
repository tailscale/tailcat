// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

// TestDeps checks that dependencies only cmd/tailcat needs stay out of
// the library package, so programs importing tailcat don't link them.
func TestDeps(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		deptest.DepChecker{
			GOOS: goos,
			BadDeps: map[string]string{
				"tailscale.com/util/qrcodes": "only cmd/tailcat's serve --qr flag prints QR codes",
			},
		}.Check(t)
	}
}
