// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"path"
	"path/filepath"
	"strings"
)

type windowsPackageRecord struct {
	displayName             string
	installLocation         string
	displayIcon             string
	portableTargetFullPath  string
	winGetInstallerType     string
	winGetPackageIdentifier string
	uninstallString         string
}

type windowsManagedRoot struct {
	owner string
	root  string
	rel   string
}

func windowsManagedRootOwner(exe string, roots []windowsManagedRoot) string {
	for _, root := range roots {
		if root.root != "" && windowsPathWithin(exe, root.root+"/"+root.rel) {
			return root.owner
		}
	}
	return ""
}

func windowsPackageRecordOwner(exe string, records []windowsPackageRecord) string {
	exe = normalizeWindowsPath(exe)
	for _, record := range records {
		owner := "the Windows installer"
		if record.winGetInstallerType != "" || record.winGetPackageIdentifier != "" ||
			strings.Contains(strings.ToLower(record.uninstallString), "winget") {
			owner = "WinGet"
		}
		if sameWindowsPath(exe, record.portableTargetFullPath) || sameWindowsPath(exe, trimDisplayIconIndex(record.displayIcon)) {
			return owner
		}
		identity := strings.ToLower(record.displayName + " " + record.winGetPackageIdentifier)
		if strings.Contains(identity, "tailcat") && windowsPathWithin(exe, record.installLocation) {
			return owner
		}
	}
	return ""
}

func normalizeWindowsPath(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "\""))
	v = strings.ReplaceAll(v, "\\", "/")
	return strings.ToLower(path.Clean(filepath.ToSlash(v)))
}

func sameWindowsPath(a, b string) bool {
	return b != "" && normalizeWindowsPath(a) == normalizeWindowsPath(b)
}

func windowsPathWithin(file, dir string) bool {
	if dir == "" {
		return false
	}
	file = normalizeWindowsPath(file)
	dir = strings.TrimSuffix(normalizeWindowsPath(dir), "/")
	return file == dir || strings.HasPrefix(file, dir+"/")
}

func trimDisplayIconIndex(v string) string {
	v = strings.TrimSpace(v)
	if comma := strings.LastIndexByte(v, ','); comma >= 0 {
		suffix := strings.TrimSpace(v[comma+1:])
		if suffix != "" && strings.Trim(suffix, "-0123456789") == "" {
			v = strings.TrimSpace(v[:comma])
		}
	}
	return strings.Trim(v, "\"")
}
