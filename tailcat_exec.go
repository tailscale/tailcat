// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
)

// ExecConnHandler returns a handler that runs argv for each incoming
// TCP connection, inetd-style: the connection is the command's
// standard input and output, and the command's standard error is the
// server's own. The command's environment is the server's plus the
// variables described by [Server.PeerEnv].
//
// Each direction is half-closed independently: the command's standard
// input reaches EOF when the client shuts down its sending side, and
// the client sees a TCP FIN when the command closes its standard
// output (typically by exiting). The connection is closed once the
// command has exited.
func (s *Server) ExecConnHandler(argv []string) func(net.Conn) {
	return func(c net.Conn) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), s.PeerEnv(c.LocalAddr(), c.RemoteAddr())...)
		cmd.Stderr = os.Stderr
		if err := runConnCommand(c, cmd); err != nil {
			s.lb.logf("exec %v: %v", argv[0], err)
		}
	}
}

// PeerEnv returns environment variables describing the peer of an
// accepted connection, given its local and remote addresses, for
// processes served to it:
//
//   - TAILCAT_PEER_KEY: the peer's node public key, in --allow's
//     "nodekey:..." format. The tunnel has already authenticated the
//     peer by this key, so a served process can tell which peer it's
//     talking to.
//   - TAILCAT_REMOTE_ADDR: the peer's tailcat IP:port.
//   - TAILCAT_LOCAL_ADDR: the server's own IP:port the peer connected to.
func (s *Server) PeerEnv(local, remote net.Addr) []string {
	env := []string{
		"TAILCAT_REMOTE_ADDR=" + remote.String(),
		"TAILCAT_LOCAL_ADDR=" + local.String(),
	}
	if ta, ok := remote.(*net.TCPAddr); ok {
		if k, ok := s.lb.peerByIP(ta.AddrPort().Addr().Unmap()); ok {
			env = append(env, "TAILCAT_PEER_KEY="+k.String())
		}
	}
	return env
}

// runConnCommand runs cmd with c as its standard input and output and
// returns once the command has exited and c is closed. Each direction
// is copied, and half-closed at its end, independently; see
// [Server.ExecConnHandler].
func runConnCommand(c net.Conn, cmd *exec.Cmd) error {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		c.Close()
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		c.Close()
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(stdin, c)
		stdin.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(c, stdout)
		if cw, ok := c.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	// Wait closes the stdout pipe once the process exits, so the copy
	// out of it must finish first or a fast-exiting command's output
	// can be lost. The stdin copy finishes on its own: once the process
	// is gone, writes to its stdin fail.
	wg.Wait()
	err = cmd.Wait()
	closeProxyConn(c)
	if err != nil {
		return fmt.Errorf("%v exited: %w", cmd.Path, err)
	}
	return nil
}
