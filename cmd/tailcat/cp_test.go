// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitRemoteArg(t *testing.T) {
	for _, tt := range []struct {
		arg        string
		host, path string
		ok         bool
	}{
		{"tcBLOB:foo.txt", "tcBLOB", "foo.txt", true},
		{"tcBLOB:", "tcBLOB", "", true},
		{"example.com:dir/foo", "example.com", "dir/foo", true},
		{"foo.txt", "", "", false},
		{"./dir:with:colons", "", "", false},
		{`C:\Users\foo`, "", "", false},
		{"C:/Users/foo", "", "", false},
		{":leading-colon", "", "", false},
	} {
		host, path, ok := splitRemoteArg(tt.arg)
		if host != tt.host || path != tt.path || ok != tt.ok {
			t.Errorf("splitRemoteArg(%q) = %q, %q, %v; want %q, %q, %v",
				tt.arg, host, path, ok, tt.host, tt.path, tt.ok)
		}
	}
}

// TestCPUsageErrors verifies cp's argument validation, which happens
// before any scp exec.
func TestCPUsageErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"too few args", []string{"cp", "foo.txt"}},
		{"no remote arg", []string{"cp", "foo.txt", "bar.txt"}},
		{"two different servers", []string{"cp", "tcAAA:x", "tcBBB:y"}},
	} {
		root, err := parseCLI(t, tt.args...)
		if err != nil {
			t.Fatalf("%s: parse: %v", tt.name, err)
		}
		err = root.Run(t.Context())
		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("%s: err = %v; want a usageError", tt.name, err)
		}
	}
}

func TestCPRejectsInvalidAddr(t *testing.T) {
	err := clientCPMode(false, false, "22", []string{"local.txt", "tc%:remote.txt"})
	if err == nil || !strings.Contains(err.Error(), "base64 decode") {
		t.Fatalf("clientCPMode error = %v; want an invalid base64 error", err)
	}
}

// TestRecvDropBox copies a file into a "tailcat recv" server and
// checks that it lands, that a second copy of another name works,
// and that reading anything back is refused (write-only drop box).
func TestRecvDropBox(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("scp"); err != nil {
		t.Skipf("no scp in $PATH: %v", err)
	}
	e := newTestEnv(t)

	recvDir := t.TempDir()
	_, addr, _ := e.startServer("recv", recvDir)

	src := filepath.Join(t.TempDir(), "gift.txt")
	const content = "drop box content"
	if err := os.WriteFile(src, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "cp", src, addr+":").CombinedOutput()
	if err != nil {
		t.Fatalf("cp into recv: %v\n%s", err, out)
	}
	matches, err := filepath.Glob(filepath.Join(recvDir, "gift.*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("received files = %q; want one timestamped gift file", matches)
	}
	v, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != content {
		t.Errorf("received content = %q; want %q", v, content)
	}

	back := filepath.Join(t.TempDir(), "back.txt")
	out, err = e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "cp", addr+":gift.txt", back).CombinedOutput()
	if err == nil {
		t.Errorf("cp out of a write-only drop box succeeded:\n%s", out)
	}
}

// TestCPRoundTrip copies a file to a read-write file server with
// "tailcat cp" (which runs the system scp) and fetches it back.
func TestCPRoundTrip(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("scp"); err != nil {
		t.Skipf("no scp in $PATH: %v", err)
	}
	e := newTestEnv(t)

	serveDir := t.TempDir()
	_, addr, _ := e.startServer("serve", "--files="+serveDir+":rw")

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "src.txt")
	const content = "cp round trip content"
	if err := os.WriteFile(src, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "cp", src, addr+":uploaded.txt").CombinedOutput()
	if err != nil {
		t.Fatalf("cp upload: %v\n%s", err, out)
	}
	v, err := os.ReadFile(filepath.Join(serveDir, "uploaded.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != content {
		t.Errorf("uploaded content = %q; want %q", v, content)
	}

	back := filepath.Join(srcDir, "back.txt")
	out, err = e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "cp", addr+":uploaded.txt", back).CombinedOutput()
	if err != nil {
		t.Fatalf("cp download: %v\n%s", err, out)
	}
	v, err = os.ReadFile(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != content {
		t.Errorf("downloaded content = %q; want %q", v, content)
	}
}
