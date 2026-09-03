// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package tailcat_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

// testSSHEnv holds the shared state for SSH tests: a tailcat server with SSH
// enabled and a connected client, all using a localhost DERP relay.
type testSSHEnv struct {
	client *tailcat.Client
}

func setupSSHEnv(t *testing.T, options ...tailcat.SSHOptions) *testSSHEnv {
	t.Helper()
	if len(options) > 1 {
		t.Fatal("setupSSHEnv takes at most one SSHOptions")
	}

	// Hermetic localhost DERP+STUN server.
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	region := derpMap.Regions[1]

	logf := logger.Discard
	if testing.Verbose() {
		logf = t.Logf
	}
	srv := &tailcat.Server{Logf: logf, Region: region}
	t.Cleanup(func() { srv.Close() })

	sshHandler := srv.HandleTailscaleSSHConn
	if len(options) == 1 {
		sshHandler = srv.SSHConnHandler(options[0])
	}
	srv.OnTCP = func(port uint16) func(net.Conn) {
		if port == 22 {
			return sshHandler
		}
		return nil
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &tailcat.Client{Server: srv.TailcatAddr(), Logf: logf}
	t.Cleanup(func() { client.Close() })

	tailcat.PingForTest(t, srv, client)

	return &testSSHEnv{client: client}
}

// sshClient dials the server's SSH port and returns a connected gossh.Client.
func (e *testSSHEnv) sshClient(t *testing.T) *gossh.Client {
	t.Helper()
	c, err := e.dialSSHClient(t, &gossh.ClientConfig{
		User:            "test",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func (e *testSSHEnv) dialSSHClient(t *testing.T, config *gossh.ClientConfig) (*gossh.Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := e.client.DialTCPPort(ctx, 22)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, "server", config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return gossh.NewClient(sshConn, chans, reqs), nil
}

func TestSSHPublicKeyAuthentication(t *testing.T) {
	t.Parallel()
	newSigner := func() gossh.Signer {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := gossh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	authorized := newSigner()
	unauthorized := newSigner()
	env := setupSSHEnv(t, tailcat.SSHOptions{
		Shell:          true,
		AuthorizedKeys: []string{string(gossh.MarshalAuthorizedKey(authorized.PublicKey()))},
	})

	config := func(signer gossh.Signer) *gossh.ClientConfig {
		c := &gossh.ClientConfig{
			User:            "test",
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		}
		if signer != nil {
			c.Auth = []gossh.AuthMethod{gossh.PublicKeys(signer)}
		}
		return c
	}
	for _, tt := range []struct {
		name   string
		signer gossh.Signer
	}{
		{"no key", nil},
		{"unlisted key", unauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := env.dialSSHClient(t, config(tt.signer))
			if err == nil {
				c.Close()
				t.Fatal("SSH authentication succeeded; want failure")
			}
		})
	}

	c, err := env.dialSSHClient(t, config(authorized))
	if err != nil {
		t.Fatalf("authorized SSH client: %v", err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.Output("echo authenticated")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "authenticated" {
		t.Errorf("output = %q; want authenticated", got)
	}

	sess, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	nl := "\n"
	if runtime.GOOS == "windows" {
		nl = "\r"
	}
	io.WriteString(stdin, "echo authenticated-interactive"+nl)
	io.WriteString(stdin, "exit"+nl)
	if err := sess.Wait(); err != nil {
		t.Logf("Wait: %v (may be expected)", err)
	}
	if !strings.Contains(stdout.String(), "authenticated-interactive") {
		t.Fatalf("authenticated interactive shell output missing marker: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Connected via tailcat SSH.") {
		t.Fatalf("authenticated interactive shell output missing MOTD: %q", stdout.String())
	}
}

func TestSSHInteractiveMOTDRequiresPTY(t *testing.T) {
	t.Parallel()

	env := setupSSHEnv(t)
	sess, err := env.sshClient(t).NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	io.WriteString(stdin, "echo no-pty\nexit\n")
	if err := sess.Wait(); err != nil {
		t.Logf("Wait: %v (may be expected)", err)
	}
	if strings.Contains(stdout.String(), "Connected via tailcat SSH.") {
		t.Fatalf("non-PTY shell output contains MOTD: %q", stdout.String())
	}
}

func TestSSHSuite(t *testing.T) {
	t.Parallel()

	env := setupSSHEnv(t)

	t.Run("ExecSimple", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		out, err := sess.Output("echo hello-from-ssh")
		if err != nil {
			t.Fatalf("Output: %v", err)
		}
		if got := strings.TrimSpace(string(out)); got != "hello-from-ssh" {
			t.Fatalf("got %q, want %q", got, "hello-from-ssh")
		}
	})

	t.Run("ExitCode", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		err = sess.Run("exit 42")
		if err == nil {
			t.Fatal("expected non-zero exit")
		}
		exitErr, ok := err.(*gossh.ExitError)
		if !ok {
			t.Fatalf("expected *gossh.ExitError, got %T: %v", err, err)
		}
		if exitErr.ExitStatus() != 42 {
			t.Fatalf("got exit code %d, want 42", exitErr.ExitStatus())
		}
	})

	t.Run("Stderr", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		// Windows PowerShell 5.1 has no && operator.
		cmd := "echo out-marker && echo err-marker >&2"
		if runtime.GOOS == "windows" {
			cmd = "echo out-marker; [Console]::Error.WriteLine('err-marker')"
		}

		var stdout, stderr bytes.Buffer
		sess.Stdout = &stdout
		sess.Stderr = &stderr
		if err := sess.Run(cmd); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !strings.Contains(stdout.String(), "out-marker") {
			t.Fatalf("stdout missing 'out-marker': %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "err-marker") {
			t.Fatalf("stderr missing 'err-marker': %q", stderr.String())
		}
		// Stderr should NOT appear in stdout (non-PTY mode keeps them separate).
		if strings.Contains(stdout.String(), "err-marker") {
			t.Fatalf("stderr leaked into stdout: %q", stdout.String())
		}
	})

	t.Run("EnvForwarding", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		// The server accepts TERM, LANG, and LC_* env vars.
		if err := sess.Setenv("LANG", "test-lang-val"); err != nil {
			t.Fatalf("Setenv LANG: %v", err)
		}
		if err := sess.Setenv("LC_ALL", "test-lc-val"); err != nil {
			t.Fatalf("Setenv LC_ALL: %v", err)
		}
		cmd := "echo LANG=$LANG LC_ALL=$LC_ALL"
		if runtime.GOOS == "windows" {
			cmd = `echo "LANG=$env:LANG LC_ALL=$env:LC_ALL"`
		}
		out, err := sess.Output(cmd)
		if err != nil {
			t.Fatalf("Output: %v", err)
		}
		got := string(out)
		if !strings.Contains(got, "LANG=test-lang-val") {
			t.Fatalf("LANG not forwarded: %q", got)
		}
		if !strings.Contains(got, "LC_ALL=test-lc-val") {
			t.Fatalf("LC_ALL not forwarded: %q", got)
		}
	})

	t.Run("PeerKeyEnv", func(t *testing.T) {
		// The served process should see the connecting peer's
		// authenticated node key in TAILCAT_PEER_KEY, matching the
		// client's own public key (in --allow's "nodekey:..." form).
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		cmd := "echo peer=$TAILCAT_PEER_KEY"
		if runtime.GOOS == "windows" {
			cmd = `echo "peer=$env:TAILCAT_PEER_KEY"`
		}
		out, err := sess.Output(cmd)
		if err != nil {
			t.Fatalf("Output: %v", err)
		}
		want := "peer=" + env.client.PublicKey().String()
		if got := strings.TrimSpace(string(out)); got != want {
			t.Fatalf("TAILCAT_PEER_KEY = %q, want %q", got, want)
		}
	})

	t.Run("PTYAllocated", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no tty command or /dev tty names on Windows")
		}
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		if err := sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
			t.Fatalf("RequestPty: %v", err)
		}
		out, err := sess.Output("tty")
		if err != nil {
			t.Fatalf("tty: %v; output: %s", err, out)
		}
		got := strings.TrimSpace(string(out))
		if strings.Contains(got, "not a tty") || !strings.HasPrefix(got, "/dev/") {
			t.Fatalf("expected a /dev/ tty path, got %q", got)
		}
	})

	t.Run("PTYTermEnv", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		if err := sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
			t.Fatalf("RequestPty: %v", err)
		}
		cmd := "echo $TERM"
		if runtime.GOOS == "windows" {
			cmd = "echo $env:TERM"
		}
		out, err := sess.Output(cmd)
		if err != nil {
			t.Fatalf("echo TERM: %v", err)
		}
		if runtime.GOOS == "windows" {
			// ConPTY output is decorated with VT escape sequences, so
			// an exact match is not possible.
			if !strings.Contains(string(out), "xterm-256color") {
				t.Fatalf("TERM missing from output %q, want %q somewhere", out, "xterm-256color")
			}
		} else if got := strings.TrimSpace(string(out)); got != "xterm-256color" {
			t.Fatalf("TERM = %q, want %q", got, "xterm-256color")
		}
	})

	t.Run("InteractiveShell", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{
			gossh.ECHO: 0, // disable echo to simplify output parsing
		}); err != nil {
			t.Fatalf("RequestPty: %v", err)
		}

		stdin, err := sess.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		sess.Stdout = &stdout

		if err := sess.Shell(); err != nil {
			t.Fatalf("Shell: %v", err)
		}

		// A real terminal sends \r for Enter, and Windows console
		// input does not treat a bare \n as a line ending.
		nl := "\n"
		if runtime.GOOS == "windows" {
			nl = "\r"
		}
		io.WriteString(stdin, "echo interactive-marker-12345"+nl)
		io.WriteString(stdin, "exit"+nl)

		if err := sess.Wait(); err != nil {
			// Shell exit may produce a non-zero status on some systems;
			// the important check is the output below.
			t.Logf("Wait: %v (may be expected)", err)
		}

		if !strings.Contains(stdout.String(), "interactive-marker-12345") {
			t.Fatalf("interactive shell output missing marker: %q", stdout.String())
		}
	})

	t.Run("CtrlC", func(t *testing.T) {
		sess, err := env.sshClient(t).NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
			t.Fatalf("RequestPty: %v", err)
		}
		stdin, err := sess.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		if err := sess.Shell(); err != nil {
			t.Fatalf("Shell: %v", err)
		}

		nl := "\n"
		sleep := "sleep 60"
		if runtime.GOOS == "windows" {
			nl = "\r"
			sleep = "Start-Sleep 60"
		}
		io.WriteString(stdin, sleep+nl)
		time.Sleep(2 * time.Second) // let the sleep start
		io.WriteString(stdin, "\x03")
		time.Sleep(1 * time.Second)
		io.WriteString(stdin, "echo after-intr-ok"+nl)
		io.WriteString(stdin, "exit"+nl)

		done := make(chan error, 1)
		go func() { done <- sess.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("Wait: %v (may be expected)", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("session did not exit: ^C did not interrupt the sleep")
		}
		if !strings.Contains(stdout.String(), "after-intr-ok") {
			t.Fatalf("output missing post-interrupt marker: %q", stdout.String())
		}
	})
}
