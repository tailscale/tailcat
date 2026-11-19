// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestInfoAfterHalfClose(t *testing.T) {
	x := newE2E(t)
	_, dialed, accepted := x.connect(TCP)

	// The dialing side half-closes first; the accepting side sees EOF and
	// half-closes second. Both handles stay open, and Info on either must
	// keep working instead of panicking on nil address methods.
	buf := make([]byte, 8)
	if err := CloseWrite(dialed, x.token()); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(accepted, x.token(), buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read after peer half close = %v; want io.EOF", err)
	}
	if err := CloseWrite(accepted, x.token()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)

	for _, h := range []Handle{dialed, accepted} {
		info := x.info(h)
		if info["local_address"] == nil || info["remote_address"] == nil {
			t.Fatalf("info after half close = %v; want both addresses", info)
		}
	}
}
