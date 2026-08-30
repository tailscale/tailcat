// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import (
	"fmt"
	"os"
)

func installStagedExecutable(staged, exe string) error {
	if err := os.Rename(staged, exe); err != nil {
		return fmt.Errorf("install update atomically: %w", err)
	}
	return nil
}

func cleanupUpdateBackup() {}
