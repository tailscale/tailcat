// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

// e2e runs a server and client against a local relay.
type e2e struct {
	t      *testing.T
	server Handle
	client Handle
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	dm := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	region, err := json.Marshal(dm.Regions[1])
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(fmt.Sprintf(`{"region":%s}`, region))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(server) })
	x := &e2e{t: t, server: server}
	if err := Start(server, x.token()); err != nil {
		t.Fatalf("start: %v", err)
	}
	info := x.info(server)
	client, err := NewClient(fmt.Sprintf(`{"address":%q,"derp_map_url":"none"}`, info["address"]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(client) })
	x.client = client
	return x
}

func (x *e2e) token() Handle { return testToken(x.t, 30*time.Second) }

func (x *e2e) info(h Handle) map[string]any {
	x.t.Helper()
	text, err := Info(h, x.token())
	if err != nil {
		x.t.Fatalf("info: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		x.t.Fatal(err)
	}
	return m
}

func (x *e2e) port(h Handle) uint16 {
	x.t.Helper()
	_, p, err := net.SplitHostPort(x.info(h)["local_address"].(string))
	if err != nil {
		x.t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		x.t.Fatal(err)
	}
	return uint16(n)
}

// connect listens on a fresh port, dials it, and accepts the connection.
func (x *e2e) connect(network int) (ln, dialed, accepted Handle) {
	x.t.Helper()
	ln, err := Listen(x.server, x.token(), 0, network)
	if err != nil {
		x.t.Fatalf("listen: %v", err)
	}
	dialed, err = Dial(x.client, x.token(), x.port(ln), network)
	if err != nil {
		x.t.Fatalf("dial: %v", err)
	}
	if network == UDP {
		if _, err := Write(dialed, x.token(), []byte("hello")); err != nil {
			x.t.Fatalf("first datagram: %v", err)
		}
	}
	accepted, err = Accept(ln, x.token())
	if err != nil {
		x.t.Fatalf("accept: %v", err)
	}
	return ln, dialed, accepted
}

func readAll(t *testing.T, h, token Handle) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := Read(h, token, buf)
		sb.Write(buf[:n])
		if errors.Is(err, io.EOF) {
			return sb.String()
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}

func TestE2ETCPRoundTripAndHalfClose(t *testing.T) {
	x := newE2E(t)
	ln, dialed, accepted := x.connect(TCP)
	if n, err := Write(dialed, x.token(), []byte("ping")); err != nil || n != 4 {
		t.Fatalf("write: %d, %v", n, err)
	}
	if err := CloseWrite(dialed, x.token()); err != nil {
		t.Fatalf("close write: %v", err)
	}
	if got := readAll(t, accepted, x.token()); got != "ping" {
		t.Fatalf("server read %q", got)
	}
	if ready, err := Readable(accepted); err != nil || !ready {
		t.Fatalf("readable after EOF = %v, %v", ready, err)
	}
	if n, err := Write(accepted, x.token(), []byte("pong")); err != nil || n != 4 {
		t.Fatalf("server write: %d, %v", n, err)
	}
	if err := Close(accepted); err != nil {
		t.Fatalf("close accepted: %v", err)
	}
	if got := readAll(t, dialed, x.token()); got != "pong" {
		t.Fatalf("client read %q", got)
	}
	if err := Close(dialed); err != nil {
		t.Fatal(err)
	}
	if err := Drain(x.client, x.token()); err != nil {
		t.Fatalf("drain client: %v", err)
	}
	if err := Close(ln); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(ln, x.token()); !errors.Is(err, ErrHandle) {
		t.Fatalf("accept on closed listener: %v", err)
	}
}

func TestE2EUDPRoundTripAndDeadline(t *testing.T) {
	x := newE2E(t)
	_, dialed, accepted := x.connect(UDP)
	buf := make([]byte, 64)
	n, err := Read(accepted, x.token(), buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("server read %q, %v", buf[:n], err)
	}
	if _, err := Write(accepted, x.token(), []byte("world")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	n, err = Read(dialed, x.token(), buf)
	if err != nil || string(buf[:n]) != "world" {
		t.Fatalf("client read %q, %v", buf[:n], err)
	}
	if _, err := Read(dialed, testToken(t, 50*time.Millisecond), buf); ErrorCode(err) != Timeout {
		t.Fatalf("idle UDP read = %v, want timeout", err)
	}
	if _, err := Write(accepted, x.token(), []byte("again")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	n, err = Read(dialed, x.token(), buf)
	if err != nil || string(buf[:n]) != "again" {
		t.Fatalf("read after timeout = %q, %v", buf[:n], err)
	}
	if err := CloseWrite(dialed, x.token()); ErrorCode(err) != InvalidArgument {
		t.Fatalf("UDP half-close = %v", err)
	}
	if _, err := Write(dialed, x.token(), make([]byte, 1233)); ErrorCode(err) != InvalidArgument {
		t.Fatalf("oversized datagram = %v", err)
	}
}

func TestE2EClientPingAndInfo(t *testing.T) {
	x := newE2E(t)
	if err := Drain(x.client, x.token()); err != nil {
		t.Fatalf("drain before start: %v", err)
	}
	if ms, err := Ping(x.client, x.token()); err != nil || ms < 0 {
		t.Fatalf("ping = %d, %v", ms, err)
	}
	if _, ok := x.info(x.client)["public_key"]; !ok {
		t.Fatal("client info lacks public_key")
	}
	if err := Drain(x.client, x.token()); err != nil {
		t.Fatalf("drain after ping: %v", err)
	}
}

func TestE2EListenFailureKeepsServerStarted(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	region, err := json.Marshal(dm.Regions[1])
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(fmt.Sprintf(`{"region":%s}`, region))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(server) })
	token := testToken(t, 30*time.Second)
	ln, err := Listen(server, token, 0, TCP)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	x := &e2e{t: t, server: server}
	port := x.port(ln)
	if _, err := Listen(server, token, port, TCP); err == nil {
		t.Fatal("duplicate listen succeeded")
	}
	if err := Start(server, token); err != nil {
		t.Fatalf("start after listen: %v", err)
	}
	if _, ok := x.info(server)["address"]; !ok {
		t.Fatal("server info lacks address")
	}
}

func TestE2ECloseServerRetiresTree(t *testing.T) {
	x := newE2E(t)
	ln, dialed, accepted := x.connect(TCP)
	blocked := make(chan error, 2)
	go func() { _, err := Accept(ln, testToken(t, -1)); blocked <- err }()
	go func() { _, err := Read(accepted, testToken(t, -1), make([]byte, 1)); blocked <- err }()
	time.Sleep(100 * time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- Close(x.server) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("close server: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("closing the server did not return")
	}
	for range 2 {
		select {
		case err := <-blocked:
			if ErrorCode(err) != Closed {
				t.Fatalf("blocked call after server close: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("server close did not unblock its resource tree")
		}
	}
	for name, h := range map[string]Handle{"listener": ln, "accepted": accepted} {
		if _, err := Info(h, NoCancel); !errors.Is(err, ErrHandle) {
			t.Fatalf("%s survived server close: %v", name, err)
		}
	}
	if _, err := Read(dialed, x.token(), make([]byte, 1)); err == nil {
		t.Fatal("read from dead peer succeeded")
	}
}
