// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"fmt"
	"os"
)

func installStagedExecutable(staged, exe string) error {
	backup := updateBackupPath(exe)
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous update backup: %w", err)
	}
	if err := os.Rename(exe, backup); err != nil {
		return fmt.Errorf("move current executable aside: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		rollbackErr := os.Rename(backup, exe)
		if rollbackErr != nil {
			return fmt.Errorf("install update: %v; rollback also failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("install update: %w (rolled back)", err)
	}
	// Removing the old executable fails while the current process is still
	// running from it. A later invocation cleans it up.
	_ = os.Remove(backup)
	return nil
}

func cleanupUpdateBackup() {
	exe, err := resolvedExecutablePath()
	if err == nil {
		_ = os.Remove(updateBackupPath(exe))
	}
}
