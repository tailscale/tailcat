// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The exec tests run sh and cat on the server side.

//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServeExec runs a server whose exec service runs a shell command
// for each connection, inetd-style, and checks that a plain client's
// stdin reaches the command, the command's stdout reaches the client,
// and the command sees the peer's node key.
func TestServeExec(t *testing.T) {
	t.Parallel()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh in $PATH: %v", err)
	}
	e := newTestEnv(t)
	_, addr, serverStderr := e.startServer("serve", "exec", "--", "sh", "-c", `cat; echo "peer=$TAILCAT_PEER_KEY"`)
	waitForLog(t, serverStderr, "# Running "+sh+" -c cat; echo \"peer=$TAILCAT_PEER_KEY\" for each connection\n")

	clientKey := filepath.Join(t.TempDir(), "c.private.json")
	if out, err := e.cmd("genkey", "--client", "--key="+clientKey).CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}
	pub, err := e.cmd("--key="+clientKey, "printpub").Output()
	if err != nil {
		t.Fatalf("printpub: %v", err)
	}

	const payload = "through the exec service\n"
	got, err := runClient(t, e.cmd("--key="+clientKey, "--derpmap-url="+e.derpMapURL, addr, "4321"), serverStderr, payload)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	want := payload + "peer=" + strings.TrimSpace(string(pub)) + "\n"
	if got != want {
		t.Errorf("client got %q; want %q", got, want)
	}
}

// TestServeExecRequiresCommand verifies that the exec service without
// a command, and a -- with no command, are rejected at startup.
func TestServeExecRequiresCommand(t *testing.T) {
	t.Parallel()
	bin := buildTailcat(t)
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"serve", "exec"}, "requires a command after --"},
		{[]string{"serve", "exec", "--"}, "no command given after --"},
		{[]string{"serve", "--", "definitely-not-a-program-tailcat-test"}, "exec command:"},
		{[]string{"serve", "no-auth-ssh,files", "--", "cat"}, "cannot be served with an SSH -- command"},
		{[]string{"tcSOMEBLOB", "80", "--", "cat"}, "only valid in server mode"},
	} {
		out, err := exec.Command(bin, tt.args...).CombinedOutput()
		if err == nil {
			t.Errorf("tailcat %v succeeded; want failure", tt.args)
			continue
		}
		if !strings.Contains(string(out), tt.want) {
			t.Errorf("tailcat %v output = %q; want %q", tt.args, out, tt.want)
		}
	}
}

// TestServeNoAuthSSHExec runs a no-auth-ssh server with a forced
// command and connects with "tailcat ssh", requesting a different
// command: the forced one runs instead, sees the requested one in
// SSH_ORIGINAL_COMMAND, and gets the client's stdin.
func TestServeNoAuthSSHExec(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("no ssh client in $PATH: %v", err)
	}
	e := newTestEnv(t)

	_, addr, stderr := e.startServer("serve", "no-auth-ssh", "--", "sh", "-c", `cat; echo "cmd=$SSH_ORIGINAL_COMMAND"`)
	waitForLog(t, stderr, "# ⚠️ WARNING: no-auth-ssh runs the command for anyone with this address; keep it secret (never in a DNS TXT record) or restrict clients with --allow\n")

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, e.bin, "--key=new", "--derpmap-url="+e.derpMapURL, "ssh", addr, "echo", "hi")
	client.Env = e.env
	client.Stdin = strings.NewReader("stdin line\n")
	out, err := client.CombinedOutput()
	if err != nil {
		t.Fatalf("tailcat ssh: %v\n%s", err, out)
	}
	if got, want := string(out), "stdin line\ncmd=echo hi\n"; got != want {
		t.Errorf("tailcat ssh output = %q; want %q", got, want)
	}
}

// TestServeSSHExec runs an authorized-keys ssh server with a forced
// command and checks, with the system ssh client, that a session
// runs it both over pipes and on a PTY, and that the SFTP subsystem
// is not offered.
func TestServeSSHExec(t *testing.T) {
	t.Parallel()
	sshExe, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("no ssh in $PATH: %v", err)
	}
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skipf("no ssh-keygen in $PATH: %v", err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skipf("no cat in $PATH: %v", err)
	}
	e := newTestEnv(t)

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if out, err := exec.Command(sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	_, addr, stderr := e.startServer("serve", "--ssh-authorized-keys="+keyPath+".pub", "ssh", "--", "cat")
	waitForLog(t, stderr, "# SSH sessions run only "+cat+"\n")
	proxyCommand, err := sshProxyCommand(e.bin, "new", e.derpMapURL, addr, "22")
	if err != nil {
		t.Fatal(err)
	}
	ssh := func(extra ...string) *exec.Cmd {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)
		args := append([]string{
			"-F", os.DevNull, // not the developer's ssh config: ControlMaster and friends
			"-i", keyPath,
			"-o", "IdentitiesOnly yes",
			"-o", "UpdateHostKeys no",
			"-o", "StrictHostKeyChecking no",
			"-o", "UserKnownHostsFile " + filepath.Join(t.TempDir(), "known_hosts"),
			"-o", "LogLevel ERROR",
			"-o", "ProxyCommand=" + proxyCommand,
		}, extra...)
		client := exec.CommandContext(ctx, sshExe, args...)
		client.Env = e.env
		return client
	}

	client := ssh("-T", "--", sshDestHost(addr), "ignored")
	client.Stdin = strings.NewReader("forced\n")
	out, err := client.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -T: %v\n%s\nserver stderr:\n%s", err, out, stderr.String())
	}
	if got, want := string(out), "forced\n"; got != want {
		t.Errorf("ssh -T output = %q; want %q", got, want)
	}

	// -tt forces a PTY request even without a terminal. The PTY echoes
	// the input line, then cat writes it back; both with CRLF. EOT
	// makes cat exit; macOS's terminal driver echoes it visibly (as
	// "^D" and backspaces) between the two lines, Linux's doesn't.
	client = ssh("-tt", "--", sshDestHost(addr))
	client.Stdin = strings.NewReader("on a pty\n\x04")
	out, err = client.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -tt: %v\n%s\nserver stderr:\n%s", err, out, stderr.String())
	}
	if got := strings.Count(string(out), "on a pty\r\n"); got != 2 {
		t.Errorf("ssh -tt output = %q; want the line twice with CRLF (echo and cat)", out)
	}

	client = ssh("-s", "--", sshDestHost(addr), "sftp")
	if out, err := client.CombinedOutput(); err == nil {
		t.Errorf("sftp subsystem request succeeded; want failure\n%s", out)
	}
}
