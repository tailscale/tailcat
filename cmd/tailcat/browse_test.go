// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"testing"
)

func TestBrowseUsage(t *testing.T) {
	for _, args := range [][]string{
		{"browse"},
		{"browse", "tcXXXXXXXXX", "extra"},
		{"forward", "--open-browser", "tcXXXXXXXXX", "0:80", "0:443"},
	} {
		root, err := parseCLI(t, args...)
		if err != nil {
			t.Fatalf("parse %q: %v", args, err)
		}
		err = root.Run(t.Context())
		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("run %q: err = %v; want a usageError", args, err)
		}
	}
}
