//go:build android

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// termuxPrefix is where the Termux app keeps its filesystem.
const termuxPrefix = "/data/data/com.termux/files/"

// underTermux reports whether this process was started by Termux.
//
// TERMUX_VERSION is set by the Termux shell, but is lost if the process is
// re-exec'd with a cleared environment, so fall back to checking whether the
// executable itself lives in the Termux filesystem.
func underTermux() bool {
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	exe, err := os.Executable()
	return err == nil && strings.HasPrefix(exe, termuxPrefix)
}

// Android 10+ forbids exec of files in an app's private data directory, so
// Termux launches binaries through /system/bin/linker64, which inserts the
// executable's absolute path as os.Args[1]. Drop it so flag parsing sees the
// real arguments.
//
// Nothing outside Termux is touched: a binary run under, say, adb shell keeps
// os.Args exactly as the kernel delivered it.
func init() {
	if !underTermux() {
		return
	}
	if len(os.Args) < 2 || !filepath.IsAbs(os.Args[1]) {
		return
	}
	if filepath.Base(os.Args[1]) != filepath.Base(os.Args[0]) {
		return
	}
	if fi, err := os.Stat(os.Args[1]); err != nil || !fi.Mode().IsRegular() {
		return
	}
	os.Args = append(os.Args[:1:1], os.Args[2:]...)
}
