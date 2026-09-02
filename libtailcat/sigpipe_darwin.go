// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && cgo

package main

import "syscall"

// setNoSigPipe makes writes to the socket fd fail with EPIPE instead of
// raising SIGPIPE once the other end is gone. The Go runtime already
// handles SIGPIPE on its own threads, but a SIGPIPE raised on a non-Go
// thread, as when the C side writes to a dead connection, would kill the
// process. Darwin has a per-socket option for this; it is set on both
// ends of every socketpair handed out.
func setNoSigPipe(fd int) {
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_NOSIGPIPE, 1)
}
