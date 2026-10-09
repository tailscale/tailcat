// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"strings"
	"testing"

	"tailscale.com/tstest"
)

// TestSplitExecArgs verifies that the command after "--" is separated
// from the positional arguments ff leaves over, whether ff kept the
// separator (it follows a positional argument) or dropped it (it
// terminated flag parsing). Not parallel: os.Args is global.
func TestSplitExecArgs(t *testing.T) {
	tstest.AssertNotParallel(t)
	for _, tt := range []struct {
		osArgs     []string
		leftover   []string
		positional string
		exec       string
		nilExec    bool
	}{
		{
			osArgs:     []string{"tailcat", "serve", "80"},
			leftover:   []string{"80"},
			positional: "80", nilExec: true,
		},
		{
			osArgs:     []string{"tailcat", "serve", "80", "--", "cat", "--", "-n"},
			leftover:   []string{"80", "--", "cat", "--", "-n"},
			positional: "80", exec: "cat -- -n",
		},
		{
			osArgs:     []string{"tailcat", "serve", "--", "cat", "-n"},
			leftover:   []string{"cat", "-n"},
			positional: "", exec: "cat -n",
		},
		{
			osArgs:     []string{"tailcat", "--serve=exec", "--", "cat"},
			leftover:   []string{"cat"},
			positional: "", exec: "cat",
		},
		{
			osArgs:     []string{"tailcat", "serve", "exec", "--"},
			leftover:   []string{"exec", "--"},
			positional: "exec", exec: "",
		},
	} {
		os.Args = tt.osArgs
		positional, exec := splitExecArgs(tt.leftover)
		if got := strings.Join(positional, " "); got != tt.positional {
			t.Errorf("%q: positional = %q; want %q", tt.osArgs, got, tt.positional)
		}
		if (exec == nil) != tt.nilExec {
			t.Errorf("%q: exec nil = %v; want %v", tt.osArgs, exec == nil, tt.nilExec)
		}
		if got := strings.Join(exec, " "); got != tt.exec {
			t.Errorf("%q: exec = %q; want %q", tt.osArgs, got, tt.exec)
		}
	}
}
