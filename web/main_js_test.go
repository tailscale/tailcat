// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"net"
	"runtime"
	"syscall/js"
	"testing"
	"time"
)

// payloadConn is a net.Conn whose Write blocks until unblock is
// closed, keeps nothing, and sends on freed once the buffer it was
// given has been garbage collected.
type payloadConn struct {
	net.Conn // nil; only Write is used
	err      error
	unblock  chan struct{}
	freed    chan bool
}

func (c *payloadConn) Write(b []byte) (int, error) {
	runtime.AddCleanup(&b[0], func(freed chan bool) { freed <- true }, c.freed)
	<-c.unblock
	if c.err != nil {
		return 0, c.err
	}
	return len(b), nil
}

// TestWriteFreesPayload checks that the Go copy of the bytes passed
// to a conn's write can be garbage collected once its Promise has
// settled, whether the write succeeded or failed. Otherwise a page
// sending a large file keeps all of it in memory.
func TestWriteFreesPayload(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{"ok", nil},
		{"error", errors.New("write failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &payloadConn{err: tt.err, unblock: make(chan struct{}), freed: make(chan bool, 1)}
			conn := makeJSConn(c, 1, nil)
			p := conn.Call("write", js.Global().Get("Uint8Array").New(64<<10))
			// The write is still blocked here, so its Promise
			// settles after makePromise has returned.
			close(c.unblock)
			if got, want := await(p), tt.err == nil; got != want {
				t.Errorf("Promise fulfilled = %v; want %v", got, want)
			}
			if !collected(c.freed) {
				t.Error("written bytes still reachable after the Promise settled")
			}
		})
	}
}

// collected reports whether freed receives a value within a few
// garbage collections.
func collected(freed chan bool) bool {
	for range 10 {
		runtime.GC()
		select {
		case <-freed:
			return true
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}

// await blocks until the JavaScript Promise p settles and reports
// whether it was fulfilled.
func await(p js.Value) (fulfilled bool) {
	done := make(chan bool, 1)
	ok := js.FuncOf(func(this js.Value, args []js.Value) any {
		done <- true
		return nil
	})
	defer ok.Release()
	bad := js.FuncOf(func(this js.Value, args []js.Value) any {
		done <- false
		return nil
	})
	defer bad.Release()
	p.Call("then", ok, bad)
	return <-done
}
