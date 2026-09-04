// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The file service rides the SSH server, which only exists on these
// platforms, and the client side runs the system sftp.

//go:build (linux || darwin || windows) && !ts_omit_ssh

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runSFTPBatch runs the system sftp against addr with the given batch
// commands, returning its combined output and error.
func runSFTPBatch(t *testing.T, e *testEnv, addr, batch string) ([]byte, error) {
	t.Helper()
	proxyCommand, err := sshProxyCommand(e.bin, "new", e.derpMapURL, addr, "22")
	if err != nil {
		t.Fatal(err)
	}
	batchFile := filepath.Join(t.TempDir(), "batch")
	if err := os.WriteFile(batchFile, []byte(batch), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sftp",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile "+os.DevNull,
		"-o", "LogLevel ERROR",
		"-o", "ProxyCommand="+proxyCommand,
		"-b", batchFile,
		sshDestHost(addr))
	cmd.Env = e.env
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			cmd.Process.Kill()
		}
	}()
	out, err := cmd.CombinedOutput()
	close(done)
	return out, err
}

// TestLS lists a read-only file server with the native ls
// subcommand, which needs no OpenSSH binaries.
func TestLS(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	serveDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveDir, "hello.txt"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(serveDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(serveDir, "sub", "inner.txt"), []byte("inner"), 0644); err != nil {
		t.Fatal(err)
	}

	_, addr, _ := e.startServer("serve", "--files="+serveDir)

	out, err := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "ls", addr).CombinedOutput()
	if err != nil {
		t.Fatalf("ls: %v\n%s", err, out)
	}
	if got, want := string(out), "hello.txt\nsub/\n"; got != want {
		t.Errorf("ls output = %q; want %q", got, want)
	}

	out, err = e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "ls", "-l", addr+":sub").CombinedOutput()
	if err != nil {
		t.Fatalf("ls -l: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "inner.txt") || !strings.Contains(s, "-rw-") {
		t.Errorf("ls -l output = %q; want a long listing of inner.txt", s)
	}
}

// TestServeFiles runs a read-only file server for a directory and
// checks that the stock OpenSSH sftp client can fetch a file from it
// but not write one to it.
func TestServeFiles(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skipf("no sftp client in $PATH: %v", err)
	}
	e := newTestEnv(t)

	serveDir := t.TempDir()
	const content = "file service e2e content"
	if err := os.WriteFile(filepath.Join(serveDir, "hello.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, addr, _ := e.startServer("serve", "--files="+serveDir+":ro")

	fetchDir := t.TempDir()
	got := filepath.Join(fetchDir, "got.txt")
	out, err := runSFTPBatch(t, e, addr, "get /hello.txt "+got+"\n")
	if err != nil {
		t.Fatalf("sftp get: %v\n%s", err, out)
	}
	v, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != content {
		t.Errorf("fetched content = %q; want %q", v, content)
	}

	out, err = runSFTPBatch(t, e, addr, "put "+got+" /put-should-fail.txt\n")
	if err == nil {
		t.Errorf("sftp put to a read-only file server succeeded:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(serveDir, "put-should-fail.txt")); err == nil {
		t.Error("put-should-fail.txt exists in the served directory")
	}
}
