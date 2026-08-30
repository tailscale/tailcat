// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

const windowsUninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

type windowsRegistryRoot struct {
	key  registry.Key
	path string
}

func windowsPackageOwner(exe string) string {
	if owner := windowsManagedRootOwner(exe, []windowsManagedRoot{
		{"Scoop", os.Getenv("SCOOP"), "apps/tailcat"},
		{"Scoop", os.Getenv("SCOOP_GLOBAL"), "apps/tailcat"},
		{"Chocolatey", os.Getenv("ChocolateyInstall"), "lib/tailcat"},
	}); owner != "" {
		return owner
	}
	roots := []windowsRegistryRoot{
		{registry.CURRENT_USER, windowsUninstallKey},
		{registry.CURRENT_USER, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, windowsUninstallKey},
		{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	var records []windowsPackageRecord
	for _, root := range roots {
		records = append(records, readWindowsPackageRecords(root)...)
	}
	return windowsPackageRecordOwner(exe, records)
}

func readWindowsPackageRecords(root windowsRegistryRoot) []windowsPackageRecord {
	k, err := registry.OpenKey(root.key, root.path, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	records := make([]windowsPackageRecord, 0, len(names))
	for _, name := range names {
		subkey, err := registry.OpenKey(k, name, registry.READ)
		if err != nil {
			continue
		}
		record := windowsPackageRecord{
			displayName:             registryString(subkey, "DisplayName"),
			installLocation:         registryString(subkey, "InstallLocation"),
			displayIcon:             registryString(subkey, "DisplayIcon"),
			portableTargetFullPath:  registryString(subkey, "PortableTargetFullPath"),
			winGetInstallerType:     registryString(subkey, "WinGetInstallerType"),
			winGetPackageIdentifier: registryString(subkey, "WinGetPackageIdentifier"),
			uninstallString:         registryString(subkey, "UninstallString"),
		}
		subkey.Close()
		if record.displayName != "" || record.portableTargetFullPath != "" || record.installLocation != "" {
			records = append(records, record)
		}
	}
	return records
}

func registryString(k registry.Key, name string) string {
	value, valueType, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	if valueType == registry.EXPAND_SZ {
		if expanded, err := registry.ExpandString(value); err == nil {
			return expanded
		}
	}
	return value
}
