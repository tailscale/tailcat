// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package capi implements the resource and cancellation contracts of libtailcat.
// It is independent of cgo so its lifetime rules can be tested with the race detector.
package capi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Handle uint64

// NoCancel supplies no caller deadline or cancellation token. It is accepted
// only as a token argument, never as a registered resource handle.
const NoCancel Handle = 0

var (
	ErrHandle   = errors.New("invalid or closed tailcat handle")
	ErrType     = errors.New("incorrect tailcat handle type")
	ErrArgument = errors.New("invalid argument")
)

const (
	OK = iota
	InvalidArgument
	Closed
	Timeout
	Cancelled
	Failure
	EOF
)

func ErrorCode(err error) int {
	switch {
	case err == nil:
		return OK
	case errors.Is(err, io.EOF):
		return EOF
	case errors.Is(err, ErrArgument), errors.Is(err, ErrType):
		return InvalidArgument
	case errors.Is(err, ErrHandle), errors.Is(err, net.ErrClosed):
		return Closed
	case errors.Is(err, context.DeadlineExceeded):
		return Timeout
	case errors.Is(err, context.Canceled):
		return Cancelled
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	return Failure
}

type entry struct {
	id       Handle
	parent   Handle
	value    any
	ctx      context.Context
	cancel   context.CancelFunc
	active   sync.WaitGroup
	children map[Handle]bool
}

var registry = struct {
	sync.Mutex
	next    Handle
	entries map[Handle]*entry
}{entries: make(map[Handle]*entry)}

func register(value any, parent Handle) (Handle, error) {
	registry.Lock()
	defer registry.Unlock()
	if parent != 0 && registry.entries[parent] == nil {
		return 0, ErrHandle
	}
	registry.next++
	id := registry.next
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{id: id, parent: parent, value: value, ctx: ctx, cancel: cancel, children: make(map[Handle]bool)}
	registry.entries[id] = e
	if parent != 0 {
		registry.entries[parent].children[id] = true
	}
	return id, nil
}

// borrow increments active while holding the same lock used to retire handles.
// Close can therefore safely wait for all users after removing an entry.
func borrow(id Handle) (*entry, error) {
	registry.Lock()
	defer registry.Unlock()
	e := registry.entries[id]
	if e == nil {
		return nil, ErrHandle
	}
	e.active.Add(1)
	return e, nil
}

type cancellationToken struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewToken starts the deadline immediately from now.
// -1 means no deadline; zero means already expired. Other negative values fail.
func NewToken(timeoutNS int64) (Handle, error) {
	if timeoutNS < -1 {
		return 0, ErrArgument
	}
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutNS == -1 {
		ctx, cancel = context.WithCancel(ctx)
	} else {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutNS))
	}
	return register(&cancellationToken{ctx, cancel}, 0)
}

func Cancel(id Handle) error {
	e, err := borrow(id)
	if err != nil {
		return err
	}
	defer e.active.Done()
	token, ok := e.value.(*cancellationToken)
	if !ok {
		return ErrType
	}
	token.cancel()
	return nil
}

func tokenContext(id Handle) (context.Context, error) {
	if id == NoCancel {
		return context.Background(), nil
	}
	e, err := borrow(id)
	if err != nil {
		return nil, err
	}
	defer e.active.Done()
	token, ok := e.value.(*cancellationToken)
	if !ok {
		return nil, ErrType
	}
	return token.ctx, nil
}

func use[T any](id, tokenID Handle, fn func(context.Context, *entry, T) error) error {
	e, err := borrow(id)
	if err != nil {
		return err
	}
	defer e.active.Done()
	value, ok := e.value.(T)
	if !ok {
		return ErrType
	}
	ctx, err := tokenContext(tokenID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	defer func() { stop(); cancel() }()
	if e.ctx.Err() != nil {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = fn(ctx, e, value)
	if err != nil && e.ctx.Err() != nil {
		return net.ErrClosed
	}
	return err
}

// Close retires the complete resource tree before cancelling any work. Accepted
// connections belong to the server, not the listener. No blocking work holds the
// registry lock. Go references borrowed by an active call remain alive throughout.
func Close(id Handle) error {
	registry.Lock()
	var retired []*entry
	var retire func(Handle)
	retire = func(h Handle) {
		e := registry.entries[h]
		if e == nil {
			return
		}
		delete(registry.entries, h)
		if p := registry.entries[e.parent]; p != nil {
			delete(p.children, h)
		}
		for child := range e.children {
			retire(child)
		}
		retired = append(retired, e)
	}
	retire(id)
	registry.Unlock()
	if len(retired) == 0 {
		return ErrHandle
	}
	for _, e := range retired {
		e.cancel()
		switch v := e.value.(type) {
		case *cancellationToken:
			v.cancel()
		case *connection:
			v.close()
		case *listener:
			v.ln.Close()
		}
	}
	var result error
	for _, e := range retired {
		e.active.Wait()
		switch v := e.value.(type) {
		case *connection:
			<-v.pumpDone
		case *client:
			result = errors.Join(result, v.client.Close())
		case *server:
			result = errors.Join(result, v.server.Close())
		}
	}
	return result
}

type gate chan struct{}

func newGate() gate { return make(gate, 1) }

func (g gate) lock(ctx context.Context) error {
	select {
	case g <- struct{}{}:
		if err := ctx.Err(); err != nil {
			g.unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g gate) unlock() { <-g }
