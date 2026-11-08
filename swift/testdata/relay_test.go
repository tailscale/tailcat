// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package swift_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

// TestSwift keeps a local DERP/STUN fixture alive for the Swift test process.
// testdata is excluded from go test ./..., so this runs only via make -C swift test.
func TestSwift(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	region, err := json.Marshal(dm.Regions[1])
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "swift", "test", "-Xswiftc", "-warnings-as-errors")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "TAILCAT_TEST_REGION="+string(region))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
