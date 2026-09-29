// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"
)

func testToken(t *testing.T, timeout time.Duration) Handle {
	t.Helper()
	h, err := NewToken(int64(timeout))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(h) })
	return h
}

func testPipe(t *testing.T) (Handle, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	h, err := register(newConnection(a, TCP), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(h); b.Close() })
	return h, b
}

func TestCancelledReadDoesNotPoisonNextRead(t *testing.T) {
	h, remote := testPipe(t)
	token := testToken(t, -1)
	done := make(chan error, 1)
	go func() { _, err := Read(h, token, make([]byte, 8)); done <- err }()
	if err := Cancel(token); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not unblock read")
	}
	go remote.Write([]byte("ok"))
	buf := make([]byte, 8)
	n, err := Read(h, testToken(t, time.Second), buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("next read = %q, %v", buf[:n], err)
	}
}

func TestCloseUnblocksReadAndRejectsStaleHandle(t *testing.T) {
	h, _ := testPipe(t)
	done := make(chan error, 1)
	go func() { _, err := Read(h, testToken(t, -1), make([]byte, 8)); done <- err }()
	if err := Close(h); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if ErrorCode(err) != Closed {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock read")
	}
	if _, err := Write(h, testToken(t, time.Second), []byte("x")); !errors.Is(err, ErrHandle) {
		t.Fatalf("write: %v", err)
	}
}

func TestDeadlineIncludesWaitingForAnotherRead(t *testing.T) {
	h, _ := testPipe(t)
	e, _ := borrow(h)
	c := e.value.(*connection)
	e.active.Done()
	if err := c.readGate.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.readGate.unlock()
	_, err := Read(h, testToken(t, 10*time.Millisecond), make([]byte, 1))
	if ErrorCode(err) != Timeout {
		t.Fatalf("read = %v", err)
	}
}

func TestReadabilityDoesNotConsumePayload(t *testing.T) {
	h, remote := testPipe(t)
	go remote.Write([]byte("hello"))
	// The probe may race with delivery but must never discard a byte.
	Readable(h)
	buf := make([]byte, 5)
	n, err := Read(h, testToken(t, time.Second), buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("read = %q, %v", buf[:n], err)
	}
}

func TestReadabilityReportsPeerEOF(t *testing.T) {
	h, remote := testPipe(t)
	remote.Close()
	deadline := time.Now().Add(time.Second)
	for {
		ready, err := Readable(h)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer EOF never became readable")
		}
		runtime.Gosched()
	}
	if n, err := Read(h, testToken(t, time.Second), make([]byte, 1)); n != 0 || ErrorCode(err) != EOF {
		t.Fatalf("read after EOF probe: %d, %v", n, err)
	}
}

func TestInvalidConfigurationDoesNotEchoSecrets(t *testing.T) {
	_, err := NewClient(`{"address":"secret-address"}`)
	if ErrorCode(err) != InvalidArgument {
		t.Fatalf("new client: %v", err)
	}
	_, err = NewServer(`{"key":"secret-key"}`)
	if err == nil || err.Error() != "invalid argument: invalid private key" {
		t.Fatalf("new server: %v", err)
	}
}
