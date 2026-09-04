// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package tailcat

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	ssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
)

const sshInteractiveMOTD = "🐈 Connected via tailcat SSH.\r\n"

// SupportsSSHServer reports whether the platform supports running the built-in
// SSH server.
func SupportsSSHServer() bool { return true }

// HandleTailscaleSSHConn handles an incoming TCP connection as an SSH session
// with a shell enabled. See [Server.SSHConnHandler] for the details.
func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	s.SSHConnHandler(SSHOptions{Shell: true})(c)
}

// SSHConnHandler returns a handler that serves an incoming TCP
// connection as an SSH session with the capabilities in opts.
// Authentication is controlled by opts.AuthorizedKeys. Configured public keys
// require a client match; zero-value options rely on the WireGuard tunnel for
// client identity.
// The connection is served using the gliderlabs/ssh library with a single
// ed25519 host key generated on first use under tailcat/ssh in the user's
// config directory (os.UserConfigDir).
//
// With opts.Shell, two session modes are supported: if the SSH client
// sends a command, it is run by the user's shell (PowerShell on
// Windows); otherwise an interactive login shell is started with a
// PTY. The SFTP subsystem is served per opts.Files; see [SSHOptions].
func (s *Server) SSHConnHandler(opts SSHOptions) func(net.Conn) {
	publicKeyHandler, authErr := sshPublicKeyHandler(opts.AuthorizedKeys)
	return func(c net.Conn) {
		if authErr != nil {
			s.lb.logf("SSH authorized keys: %v", authErr)
			c.Close()
			return
		}
		keys, err := getHostKeys()
		if err != nil {
			s.lb.logf("SSH host keys: %v", err)
			c.Close()
			return
		}
		handler := sessionHandler
		if !opts.Shell {
			handler = func(sess ssh.Session) {
				fmt.Fprintf(sess.Stderr(), "this tailcat server only offers file transfer (SFTP); shell and exec sessions are disabled\r\n")
				sess.Exit(1)
			}
		}
		subsystems := map[string]ssh.SubsystemHandler{}
		if h := s.sftpSubsystemHandler(opts); h != nil {
			subsystems["sftp"] = h
		}
		srv := &ssh.Server{
			Handler:           handler,
			PublicKeyHandler:  publicKeyHandler,
			ChannelHandlers:   map[string]ssh.ChannelHandler{"session": ssh.DefaultSessionHandler},
			RequestHandlers:   map[string]ssh.RequestHandler{},
			SubsystemHandlers: subsystems,
		}
		if publicKeyHandler == nil {
			srv.NoClientAuthHandler = func(ctx ssh.Context) error { return nil }
		}
		for _, k := range keys {
			srv.AddHostKey(k)
		}
		srv.HandleConn(c)
	}
}

// sessionHandler handles a single SSH session (shell or exec).
func sessionHandler(sess ssh.Session) {
	u, err := user.Current()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "failed to get current user: %v\r\n", err)
		sess.Exit(1)
		return
	}

	// newSessionCommand is per-platform (tailcat_ssh_unix.go,
	// tailcat_ssh_windows.go). It returns an unstarted command with
	// Args, Dir, and the base environment set.
	cmd := newSessionCommand(u, sess.RawCommand())
	for _, env := range sess.Environ() {
		if acceptEnvPair(env) {
			cmd.Env = append(cmd.Env, env)
		}
	}

	ptyReq, winCh, isPTY := sess.Pty()
	if isPTY && sess.RawCommand() == "" {
		io.WriteString(sess, sshInteractiveMOTD)
	}
	if isPTY {
		sess.DisablePTYEmulation()
		runWithPTY(sess, cmd, ptyReq, winCh)
	} else {
		runWithPipes(sess, cmd)
	}
}

// runWithPipes runs cmd with stdin/stdout/stderr pipes (no PTY).
func runWithPipes(sess ssh.Session, cmd *exec.Cmd) {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "stdin pipe: %v\r\n", err)
		sess.Exit(1)
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "stdout pipe: %v\r\n", err)
		sess.Exit(1)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "stderr pipe: %v\r\n", err)
		sess.Exit(1)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(sess.Stderr(), "start: %v\r\n", err)
		sess.Exit(1)
		return
	}

	go func() {
		defer stdinPipe.Close()
		io.Copy(stdinPipe, sess)
	}()

	outputDone := make(chan struct{})
	var openStreams atomic.Int32
	openStreams.Store(2) // stdout + stderr
	closeOutput := func() {
		if openStreams.Add(-1) == 0 {
			close(outputDone)
		}
	}
	go func() {
		defer closeOutput()
		io.Copy(sess, stdoutPipe)
	}()
	go func() {
		defer closeOutput()
		io.Copy(sess.Stderr(), stderrPipe)
	}()

	// Drain stdout/stderr before calling Wait: Wait closes the pipes
	// once the process exits, racing the copies and sometimes losing
	// the output of fast-exiting commands. (The copies finish on
	// their own: the pipes read EOF when the process exits.)
	<-outputDone
	err = cmd.Wait()

	if err != nil {
		sess.Exit(exitCode(err))
		return
	}
	sess.Exit(0)
}

// exitCode extracts the exit code from an exec error.
func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

// acceptEnvPair reports whether the environment variable key=value pair
// should be accepted from the client (same default as OpenSSH AcceptEnv).
func acceptEnvPair(kv string) bool {
	k, _, ok := strings.Cut(kv, "=")
	if !ok {
		return false
	}
	return k == "TERM" || k == "LANG" || strings.HasPrefix(k, "LC_")
}

// getHostKeys returns the SSH host key signers, generating an ed25519 key
// in the tailcat/ssh config directory if one doesn't exist.
func getHostKeys() ([]gossh.Signer, error) {
	dir, err := sshKeyDir()
	if err != nil {
		return nil, err
	}
	keyPEM, err := hostKeyFileOrCreate(dir)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing host key: %w", err)
	}
	return []gossh.Signer{signer}, nil
}

func sshKeyDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("UserConfigDir: %w", err)
	}
	dir := filepath.Join(cfgDir, "tailcat", "ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// hostKeyMu protects concurrent generation of host keys with
// [getHostKeys], making sure two callers don't try to concurrently find
// a missing key and generate it at the same time, returning different keys to
// their callers.
var hostKeyMu sync.Mutex

func hostKeyFileOrCreate(keyDir string) ([]byte, error) {
	hostKeyMu.Lock()
	defer hostKeyMu.Unlock()

	path := filepath.Join(keyDir, "ssh_host_ed25519_key")
	v, err := os.ReadFile(path)
	if err == nil {
		return v, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, err
	}
	return pemData, nil
}
