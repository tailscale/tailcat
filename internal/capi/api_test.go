// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"tailscale.com/types/key"
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

// TestAllowClientKeepsAllowlistSemantics checks that the C API keeps
// its allowlist semantics on top of [tailcat.Server.AllowClient]: an
// empty list admits any client, and adding a key restricts admission.
func TestAllowClientKeepsAllowlistSemantics(t *testing.T) {
	k1, k2, k3 := key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public()
	admits := func(h Handle, k key.NodePublic) bool {
		t.Helper()
		var ok bool
		if err := use[*server](h, NoCancel, func(ctx context.Context, e *entry, s *server) error {
			ok = s.server.AllowClient(k)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	open, err := NewServer(`{}`)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(open)
	if !admits(open, k1) {
		t.Errorf("server with empty allowlist rejected a client")
	}
	if err := AllowClient(open, NoCancel, k1.String()); err != nil {
		t.Fatal(err)
	}
	if !admits(open, k1) || admits(open, k2) {
		t.Errorf("after adding k1: admits k1, k2 = %v, %v; want true, false", admits(open, k1), admits(open, k2))
	}

	listed, err := NewServer(fmt.Sprintf(`{"allowed_clients":[%q]}`, k1.String()))
	if err != nil {
		t.Fatal(err)
	}
	defer Close(listed)
	if !admits(listed, k1) || admits(listed, k2) {
		t.Errorf("configured with k1: admits k1, k2 = %v, %v; want true, false", admits(listed, k1), admits(listed, k2))
	}
	if err := AllowClient(listed, NoCancel, k3.String()); err != nil {
		t.Fatal(err)
	}
	if !admits(listed, k3) {
		t.Errorf("added k3 not admitted")
	}
}
