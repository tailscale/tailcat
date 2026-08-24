// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"
	"time"

	"github.com/tailscale/tailcat/libtailcat/ctest"
)

func TestConn(t *testing.T) {
	ctest.RunTestConn(t)
	waitDrained(t)
}

// waitDrained waits for the C test's teardown to empty all the
// bookkeeping maps, catching leaked handles, listeners, or conns.
func waitDrained(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		handles.mu.Lock()
		nh := len(handles.m)
		handles.mu.Unlock()
		listeners.mu.Lock()
		nl := len(listeners.m)
		listeners.mu.Unlock()
		conns.mu.Lock()
		nc := len(conns.m)
		conns.mu.Unlock()
		if nh == 0 && nl == 0 && nc == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaked: %d handles, %d listeners, %d conns", nh, nl, nc)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
