// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && !darwin

package main

// setNoSigPipe is a no-op here: only Darwin has a per-socket SO_NOSIGPIPE
// option. Non-Go threads writing to a dead connection on other platforms
// should ignore SIGPIPE themselves (see sigpipe_darwin.go).
func setNoSigPipe(fd int) {}
