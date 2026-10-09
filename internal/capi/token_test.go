// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNoCancelHasNoDeadlineOrCancellation(t *testing.T) {
	ctx, err := tokenContext(NoCancel)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ctx.Deadline(); ok || ctx.Done() != nil || ctx.Err() != nil {
		t.Fatal("no-cancel context has a deadline or cancellation signal")
	}
}

func TestNoCancelSupportsReadAndWrite(t *testing.T) {
	h, remote := testPipe(t)
	written := make(chan error, 1)
	go func() { _, err := remote.Write([]byte("hello")); written <- err }()
	buffer := make([]byte, 5)
	if n, err := Read(h, NoCancel, buffer); err != nil || string(buffer[:n]) != "hello" {
		t.Fatalf("read = %q, %v", buffer[:n], err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	read := make(chan string, 1)
	go func() {
		b := make([]byte, 5)
		n, _ := remote.Read(b)
		read <- string(b[:n])
	}()
	if n, err := Write(h, NoCancel, []byte("world")); err != nil || n != 5 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if got := <-read; got != "world" {
		t.Fatalf("peer received %q", got)
	}
}

func TestNoCancelIsNotAResourceHandle(t *testing.T) {
	for name, fn := range map[string]func() error{
		"cancel": func() error { return Cancel(NoCancel) },
		"close":  func() error { return Close(NoCancel) },
		"info":   func() error { _, err := Info(NoCancel, NoCancel); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := fn(); ErrorCode(err) != Closed {
				t.Fatalf("got %v, want TC_CLOSED", err)
			}
		})
	}
}

func TestNoCancelStillObservesResourceClosure(t *testing.T) {
	for _, closeParent := range []bool{false, true} {
		name := "resource"
		if closeParent {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			parent, err := register(struct{}{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { Close(parent) })
			resource, err := register(struct{}{}, parent)
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan context.Context, 1)
			result := make(chan error, 1)
			go func() {
				result <- use[struct{}](resource, NoCancel, func(ctx context.Context, _ *entry, _ struct{}) error {
					entered <- ctx
					<-ctx.Done()
					return ctx.Err()
				})
			}()
			var ctx context.Context
			select {
			case ctx = <-entered:
			case err := <-result:
				t.Fatalf("call returned before resource closure: %v", err)
			case <-time.After(time.Second):
				t.Fatal("call never started")
			}
			if err := Cancel(NoCancel); !errors.Is(err, ErrHandle) {
				t.Fatalf("cancel sentinel: %v", err)
			}
			if err := Close(NoCancel); !errors.Is(err, ErrHandle) {
				t.Fatalf("close sentinel: %v", err)
			}
			if ctx.Err() != nil {
				t.Fatal("sentinel cancellation/closure affected resource work")
			}
			target := resource
			if closeParent {
				target = parent
			}
			closed := make(chan error, 1)
			go func() { closed <- Close(target) }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("resource closure did not finish")
			}
			if err := <-result; ErrorCode(err) != Closed {
				t.Fatalf("blocked call = %v, want TC_CLOSED", err)
			}
		})
	}
}

func TestNoCancelDoesNotRelaxNonzeroHandleValidation(t *testing.T) {
	token := testToken(t, -1)
	if token == NoCancel {
		t.Fatal("allocated token overlaps sentinel")
	}
	if err := Close(token); err != nil {
		t.Fatal(err)
	}
	if _, err := tokenContext(token); !errors.Is(err, ErrHandle) {
		t.Fatalf("closed token: %v", err)
	}
	connection, _ := testPipe(t)
	if _, err := tokenContext(connection); !errors.Is(err, ErrType) {
		t.Fatalf("wrong resource type: %v", err)
	}
}
