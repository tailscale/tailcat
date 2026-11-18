// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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
	if k, ok := s.PeerKey(remote); ok {
		env = append(env, "TAILCAT_PEER_KEY="+k.String())
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
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		io.Copy(c, stdout)
		if cw, ok := c.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	// The command may exit while the client keeps its write side open,
	// leaving a stdin copy blocked in c.Read() forever. Output EOF means
	// the command closed stdout (normally by exiting), so close the proxy
	// connection to unblock that read before waiting for the process.
	<-outputDone
	closeProxyConn(c)
	io.Copy(stdin, c)
	stdin.Close()
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%v exited: %w", cmd.Path, err)
	}
	return nil
}
