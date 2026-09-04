// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_ssh || !(linux || darwin || windows)

package tailcat

import (
	"net"
)

// SupportsSSHServer reports whether the platform supports running the built-in
// SSH server.
func SupportsSSHServer() bool { return false }

func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	c.Close()
}

// SSHConnHandler returns a handler that closes the connection; the
// SSH server is not supported on this platform or build.
func (s *Server) SSHConnHandler(opts SSHOptions) func(net.Conn) {
	return func(c net.Conn) { c.Close() }
}
