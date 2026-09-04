// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The SSH server side only exists on these platforms (see
// tailcat.SupportsSSHServer), and the client side runs the system ssh.

//go:build linux || darwin || windows

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestServeNoAuthSSH runs a --serve=no-auth-ssh server and connects
// to it with "tailcat ssh", which execs the system ssh client with a
// ProxyCommand that runs the tailcat binary itself. The exec form
// ("echo hi") never starts an interactive shell or allocates a PTY:
// the server ignores the requested SSH user and runs the current
// user's shell (PowerShell on Windows). All state stays in temp
// dirs: the server's generated host key lands under the test config
// dir, and the client runs with StrictHostKeyChecking off and a null
// known hosts file.
func TestServeNoAuthSSH(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("no ssh client in $PATH: %v", err)
	}
	e := newTestEnv(t)

	_, addr, _ := e.startServer("--serve=no-auth-ssh")

	client := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "ssh", addr, "echo", "hi")
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			client.Process.Kill()
		}
	}()
	out, err := client.CombinedOutput()
	close(done)
	if err != nil {
		t.Fatalf("tailcat ssh: %v\n%s", err, out)
	}
	// TrimSpace: PowerShell on Windows emits "hi\r\n".
	if got, want := strings.TrimSpace(string(out)), "hi"; got != want {
		t.Errorf("tailcat ssh output = %q; want %q", got, want)
	}
}

func TestServeSSHRequiresAuthorizedKeys(t *testing.T) {
	t.Parallel()
	bin := buildTailcat(t)
	out, err := exec.Command(bin, "serve", "ssh").CombinedOutput()
	if err == nil {
		t.Fatal("tailcat serve ssh succeeded without authorized keys")
	}
	if !strings.Contains(string(out), "requires --ssh-authorized-keys") {
		t.Fatalf("tailcat serve ssh output = %q; want missing authorized keys error", out)
	}
}

func TestServeSSHInteractive(t *testing.T) {
	t.Parallel()
	sshExe, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("no ssh in $PATH: %v", err)
	}
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skipf("no ssh-keygen in $PATH: %v", err)
	}
	e := newTestEnv(t)

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if out, err := exec.Command(sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	_, addr, _ := e.startServer("serve", "--ssh-authorized-keys="+keyPath+".pub", "ssh")
	proxyCommand, err := sshProxyCommand(e.bin, "new", e.derpMapURL, addr, "22")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, sshExe,
		"-tt",
		"-i", keyPath,
		"-o", "IdentitiesOnly yes",
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile "+filepath.Join(t.TempDir(), "known_hosts"),
		"-o", "LogLevel ERROR",
		"-o", "ProxyCommand="+proxyCommand,
		"--", sshDestHost(addr),
	)
	client.Env = e.env
	nl := "\n"
	if runtime.GOOS == "windows" {
		nl = "\r"
	}
	client.Stdin = strings.NewReader("echo authenticated-interactive" + nl + "exit" + nl)
	out, err := client.CombinedOutput()
	if err != nil {
		t.Fatalf("tailcat ssh: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "authenticated-interactive") {
		t.Fatalf("interactive output missing marker: %q", out)
	}
	if !strings.Contains(string(out), "Connected via tailcat SSH.") {
		t.Fatalf("interactive output missing MOTD: %q", out)
	}
}
