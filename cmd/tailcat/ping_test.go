// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"regexp"
	"strings"
	"testing"
)

// TestPing verifies the ping subcommand against a plain server, which
// survives disco pings because they never trip its
// accept-one-TCP-connection stdout mode. The --until-direct form must
// find a direct localhost path, the same mechanism "tailcat ping
// --until-direct" users rely on to verify NAT traversal.
func TestPing(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	_, addr, _ := e.startServer()

	t.Run("ping", func(t *testing.T) {
		out, err := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "ping", addr).CombinedOutput()
		if err != nil {
			t.Fatalf("ping: %v\n%s", err, out)
		}
		if !regexp.MustCompile(`(?m)^pong in .+ via .+$`).Match(out) {
			t.Errorf("ping output = %q; want a pong line", out)
		}
	})

	t.Run("until_direct", func(t *testing.T) {
		out, err := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "ping", "--until-direct", "--timeout=30s", addr).CombinedOutput()
		if err != nil {
			t.Fatalf("ping --until-direct: %v\n%s", err, out)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		last := lines[len(lines)-1]
		if !strings.HasPrefix(last, "pong in ") || strings.Contains(last, "via DERP(") {
			t.Errorf("final ping line = %q; want a pong via a direct path", last)
		}
	})
}
