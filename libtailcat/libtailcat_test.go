// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && cgo

package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"golang.org/x/sys/unix"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// The tailcat address from the README, and what "tailcat parse" shows
// for it.
const (
	readmeAddr       = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"
	readmeAddrKey    = "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34"
	readmeAddrRegion = 302
)

func mkLogger(t testing.TB, name string) logger.Logf {
	return func(format string, args ...any) {
		t.Helper()
		if t.Failed() {
			return
		}
		t.Logf("        ["+name+"] "+format, args...)
	}
}

// logPipes keeps the write ends of the log pipes alive for the life of
// the test binary: the Go side writes to their raw descriptor numbers,
// which must not be closed (and possibly reused) underneath it.
var logPipes []*os.File

// logCapture collects the lines received through a logFD pipe.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (lc *logCapture) contains(sub string) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, l := range lc.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// logFD returns a descriptor for tailcat_set_logfd whose lines are logged
// through t while the test runs, and collected in the returned capture.
func logFD(t *testing.T, name string) (cInt, *logCapture) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	logPipes = append(logPipes, w)
	lc := new(logCapture)
	var mu sync.Mutex
	done := false
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		done = true
	})
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			lc.mu.Lock()
			lc.lines = append(lc.lines, sc.Text())
			lc.mu.Unlock()
			mu.Lock()
			if !done {
				t.Logf("        [%s] %s", name, sc.Text())
			}
			mu.Unlock()
		}
	}()
	return cInt(w.Fd()), lc
}

func errmsg(h cInt) string {
	var buf [1024]cChar
	TailcatErrmsg(h, &buf[0], cSize(len(buf)))
	return goString(&buf[0])
}

// check fails the test if rc, returned by a call on handle h, isn't 0.
func check(t *testing.T, name string, h cInt, rc cInt) {
	t.Helper()
	if rc != 0 {
		t.Fatalf("%s: rc=%d: %s", name, rc, errmsg(h))
	}
}

// readBuf calls a buffer-output function and returns the string it wrote.
func readBuf(t *testing.T, name string, h cInt, fn func(*cChar, cSize) cInt) string {
	t.Helper()
	var buf [4096]cChar
	check(t, name, h, fn(&buf[0], cSize(len(buf))))
	return goString(&buf[0])
}

// gostr converts and frees a malloc'd C string.
func gostr(p *cChar) string {
	if p == nil {
		return ""
	}
	defer cFree(p)
	return goString(p)
}

func writeAll(t *testing.T, fd cInt, s string) {
	t.Helper()
	b := []byte(s)
	for len(b) > 0 {
		n, err := syscall.Write(int(fd), b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("write(%d): %v", fd, err)
		}
		b = b[n:]
	}
}

// readLine reads fd until a newline, failing on EOF or error.
func readLine(t *testing.T, fd cInt) string {
	t.Helper()
	var got []byte
	var b [256]byte
	for {
		n, err := syscall.Read(int(fd), b[:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("read(%d): %v", fd, err)
		}
		if n == 0 {
			t.Fatalf("read(%d): EOF before a newline; got %q", fd, got)
		}
		got = append(got, b[:n]...)
		if got[len(got)-1] == '\n' {
			return string(got)
		}
	}
}

// expectEOF reads fd, expecting it to return 0 bytes.
func expectEOF(t *testing.T, fd cInt) {
	t.Helper()
	var b [256]byte
	for {
		n, err := syscall.Read(int(fd), b[:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("read(%d): %v; want EOF", fd, err)
		}
		if n == 0 {
			return
		}
		t.Fatalf("read(%d) = %q; want EOF", fd, b[:n])
	}
}

// accept runs TailcatAccept on l with a timeout.
func accept(t *testing.T, l cInt, timeout time.Duration) cInt {
	t.Helper()
	type result struct {
		fd cInt
		rc cInt
	}
	ch := make(chan result, 1)
	go func() {
		var fd cInt
		rc := TailcatAccept(l, &fd)
		ch <- result{fd, rc}
	}()
	select {
	case r := <-ch:
		if r.rc != 0 {
			t.Fatalf("accept on %d: rc=%d", l, r.rc)
		}
		return r.fd
	case <-time.After(timeout):
		t.Fatalf("accept on %d: no connection after %v", l, timeout)
		return 0
	}
}

func connInfo(t *testing.T, l, c cInt) (remote string, localPort int) {
	t.Helper()
	var buf [256]cChar
	var port cInt
	if rc := TailcatConnInfo(l, c, &buf[0], cSize(len(buf)), &port); rc != 0 {
		t.Fatalf("conn_info(%d, %d): rc=%d", l, c, rc)
	}
	return goString(&buf[0]), int(port)
}

// expectCloseOnExec fails the test unless fd, a descriptor handed to C, is
// close-on-exec, so that a child process the host spawns does not inherit
// it and keep the connection alive.
func expectCloseOnExec(t *testing.T, what string, fd cInt) {
	t.Helper()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("fcntl(F_GETFD) on the %s descriptor %d: %v", what, fd, err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("the %s descriptor %d is not close-on-exec", what, fd)
	}
}

// waitFor polls cond for up to timeout.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEndToEnd(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	// Server.
	sd := TailcatServerNew()
	serverLogFD, serverLog := logFD(t, "server")
	check(t, "set_logfd", sd, TailcatSetLogFD(sd, serverLogFD))
	setServerRegionForTest(sd, reg)
	var l80, lAny cInt
	check(t, "listen 80", sd, TailcatServerListen(sd, 80, &l80))
	expectCloseOnExec(t, "listener", l80)
	if rc := TailcatServerListen(sd, 80, &lAny); rc != -1 || errmsg(sd) == "" {
		t.Fatalf("second listen on port 80: rc=%d, errmsg=%q; want -1 with a message", rc, errmsg(sd))
	}
	if rc := TailcatServerAddr(sd, new(cChar), 1); rc != -1 {
		t.Fatalf("addr before start: rc=%d; want -1", rc)
	}
	check(t, "start", sd, TailcatServerStart(sd))
	if rc := TailcatServerStart(sd); rc != -1 {
		t.Fatalf("second start: rc=%d; want -1", rc)
	}
	check(t, "listen 0", sd, TailcatServerListen(sd, 0, &lAny))
	addr := readBuf(t, "addr", sd, func(b *cChar, n cSize) cInt { return TailcatServerAddr(sd, b, n) })
	serverKey := readBuf(t, "public_key", sd, func(b *cChar, n cSize) cInt { return TailcatServerPublicKey(sd, b, n) })
	t.Logf("server address %s, key %s", addr, serverKey)
	if !strings.HasPrefix(addr, "tc") || !strings.HasPrefix(serverKey, "nodekey:") {
		t.Fatalf("malformed address %q or key %q", addr, serverKey)
	}
	var small [4]cChar
	if rc := TailcatServerAddr(sd, &small[0], cSize(len(small))); rc != cERANGE || small[3] != 0 || goString(&small[0]) != addr[:3] {
		t.Fatalf("addr into a small buffer: rc=%d, got %q; want ERANGE and a NUL-terminated prefix", rc, goString(&small[0]))
	}
	var status *cChar
	check(t, "status_json", sd, TailcatServerStatusJSON(sd, &status))
	if s := gostr(status); !json.Valid([]byte(s)) {
		t.Fatalf("status_json returned invalid JSON: %q", s)
	}

	// Client.
	caddr := cString(addr)
	defer cFree(caddr)
	cd := TailcatClientNew(caddr)
	if cd == 0 {
		t.Fatal("client_new returned 0 for the server's address")
	}
	clientLogFD, _ := logFD(t, "client")
	check(t, "client set_logfd", cd, TailcatSetLogFD(cd, clientLogFD))
	clientKey := readBuf(t, "client public_key", cd, func(b *cChar, n cSize) cInt { return TailcatClientPublicKey(cd, b, n) })
	t.Logf("client key %s", clientKey)

	// Handles of the wrong kind.
	if rc := TailcatServerStart(cd); rc != cEBADF {
		t.Fatalf("server_start on a client handle: rc=%d; want EBADF", rc)
	}
	if rc := TailcatClientPing(sd, 100, nil); rc != cEBADF {
		t.Fatalf("client_ping on a server handle: rc=%d; want EBADF", rc)
	}

	// A server with an allowlist ignores clients not on it: allow some
	// other key first and check that a ping gets no answer.
	other := cString(key.NewNode().Public().String())
	check(t, "allow other", sd, TailcatServerAllowClient(sd, other))
	cFree(other)
	var latency cDouble
	if rc := TailcatClientPing(cd, 300, &latency); rc != -1 {
		t.Fatalf("ping from a disallowed client: rc=%d; want -1", rc)
	}
	t.Logf("disallowed ping: %s", errmsg(cd))
	ckey := cString(clientKey)
	check(t, "allow client", sd, TailcatServerAllowClient(sd, ckey))
	cFree(ckey)
	// The server finishes connecting to the relay in the background
	// after start, and a ping sends a single meow that a server not yet
	// on the relay never sees, so retry until one gets through.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if rc := TailcatClientPing(cd, 2000, &latency); rc == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ping: %s", errmsg(cd))
		}
		t.Logf("ping: %s; retrying", errmsg(cd))
	}
	if latency <= 0 {
		t.Fatalf("ping latency = %v ms; want > 0", latency)
	}
	t.Logf("ping latency %.2f ms", float64(latency))
	var path *cChar
	check(t, "path_json", cd, TailcatClientPathJSON(cd, 10000, &path))
	t.Logf("path: %s", gostr(path))

	// Now that the server is known to be reachable, a client that isn't
	// allowed must be ignored: its ping times out and the server logs
	// the rejection.
	cd2 := TailcatClientNew(caddr)
	if cd2 == 0 {
		t.Fatal("client_new returned 0 for the server's address")
	}
	check(t, "client2 set_logfd", cd2, TailcatSetLogFD(cd2, -1))
	key2 := readBuf(t, "client2 public_key", cd2, func(b *cChar, n cSize) cInt { return TailcatClientPublicKey(cd2, b, n) })
	if rc := TailcatClientPing(cd2, 3000, nil); rc != -1 {
		t.Fatalf("ping from a disallowed client: rc=%d; want -1", rc)
	}
	if want := "ignoring meow from " + key2; !serverLog.contains(want) {
		t.Fatalf("server log lacks %q after a disallowed ping", want)
	}
	check(t, "client2 close", cd2, TailcatClientClose(cd2))

	// Dial, accept, exchange data both ways.
	var c1 cInt
	check(t, "dial 80", cd, TailcatClientDial(cd, 80, 10000, &c1))
	expectCloseOnExec(t, "dialed connection", c1)
	writeAll(t, c1, "hello\n")
	s1 := accept(t, l80, 10*time.Second)
	expectCloseOnExec(t, "accepted connection", s1)
	if got := readLine(t, s1); got != "hello\n" {
		t.Fatalf("server read %q; want hello", got)
	}
	remote, port := connInfo(t, l80, s1)
	if remote == "" || port != 80 {
		t.Fatalf("conn_info = %q, %d; want a remote address and port 80", remote, port)
	}
	t.Logf("accepted from %s on port %d", remote, port)
	writeAll(t, s1, "world\n")
	if got := readLine(t, c1); got != "world\n" {
		t.Fatalf("client read %q; want world", got)
	}

	// Half-close: the server sees EOF but can still answer.
	if err := syscall.Shutdown(int(c1), syscall.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, s1)
	writeAll(t, s1, "bye\n")
	if got := readLine(t, c1); got != "bye\n" {
		t.Fatalf("client read %q after half-close; want bye", got)
	}
	syscall.Close(int(s1))
	syscall.Close(int(c1))

	// The catch-all listener gets the ports nobody else listens on.
	var c2 cInt
	check(t, "dial 8080", cd, TailcatClientDial(cd, 8080, 10000, &c2))
	s2 := accept(t, lAny, 10*time.Second)
	if _, port := connInfo(t, lAny, s2); port != 8080 {
		t.Fatalf("catch-all conn_info port = %d; want 8080", port)
	}
	syscall.Close(int(s2))
	syscall.Close(int(c2))

	// Without the catch-all, an unregistered port is refused.
	syscall.Close(int(lAny))
	_, s := getServer(sd)
	waitFor(t, "the catch-all listener to unregister", 5*time.Second, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.ports[0] == nil
	})
	var c3 cInt
	if rc := TailcatClientDial(cd, 9999, 5000, &c3); rc == 0 {
		// The RST may land after the dial returned; the first read
		// must then fail promptly.
		done := make(chan struct{})
		go func() {
			defer close(done)
			var b [16]byte
			n, err := syscall.Read(int(c3), b[:])
			if n > 0 && err == nil {
				t.Errorf("read on a connection to an unregistered port got %q", b[:n])
			}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("read on a connection to an unregistered port didn't fail within 5s")
		}
		syscall.Close(int(c3))
	} else {
		t.Logf("dial to an unregistered port: rc=%d: %s", rc, errmsg(cd))
	}

	// Keys and addresses.
	var keyJSON, nodekey, keyAddr, parsed *cChar
	if e := TailcatKeyGenerate(&keyJSON); e != nil {
		t.Fatalf("key_generate: %s", gostr(e))
	}
	kj := gostr(keyJSON)
	var pk tailcat.PrivateKey
	if err := json.Unmarshal([]byte(kj), &pk); err != nil {
		t.Fatalf("key_generate JSON: %v\n%s", err, kj)
	}
	if pk.Public.RegionID != -1 || pk.Private.IsZero() {
		t.Fatalf("key_generate: RegionID=%d, private zero=%v; want -1 and a key", pk.Public.RegionID, pk.Private.IsZero())
	}
	ckj := cString(kj)
	if e := TailcatKeyPublic(ckj, &nodekey); e != nil {
		t.Fatalf("key_public: %s", gostr(e))
	}
	if got, want := gostr(nodekey), pk.Private.Public().String(); got != want {
		t.Fatalf("key_public = %q; want %q", got, want)
	}
	if e := TailcatKeyAddr(ckj, &keyAddr); e == nil || keyAddr != nil {
		t.Fatalf("key_addr on an auto-region key succeeded: %q", gostr(keyAddr))
	} else {
		t.Logf("key_addr on an auto-region key: %s", gostr(e))
	}
	cFree(ckj)
	pk.Public.RegionID = readmeAddrRegion
	fixed, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}
	cfixed := cString(string(fixed))
	if e := TailcatKeyAddr(cfixed, &keyAddr); e != nil {
		t.Fatalf("key_addr on a fixed-region key: %s", gostr(e))
	}
	cFree(cfixed)
	ci, err := tailcat.ParseAddr(tailcat.Addr(gostr(keyAddr)))
	if err != nil {
		t.Fatalf("parsing key_addr output: %v", err)
	}
	if ci.RegionID != readmeAddrRegion || ci.ServerPublic.NodePublic != pk.Private.Public() || ci.ServerDiscoPublic.IsZero() {
		t.Fatalf("key_addr output parsed to %+v", ci)
	}

	creadme := cString(readmeAddr)
	if e := TailcatAddrParse(creadme, &parsed); e != nil {
		t.Fatalf("addr_parse: %s", gostr(e))
	}
	cFree(creadme)
	var fields struct {
		ServerPublic string
		RegionID     int
	}
	pj := gostr(parsed)
	if err := json.Unmarshal([]byte(pj), &fields); err != nil {
		t.Fatalf("addr_parse JSON: %v\n%s", err, pj)
	}
	if fields.ServerPublic != readmeAddrKey || fields.RegionID != readmeAddrRegion {
		t.Fatalf("addr_parse = %+v; want key %s and region %d", fields, readmeAddrKey, readmeAddrRegion)
	}
	cbad := cString("nope")
	if e := TailcatAddrParse(cbad, &parsed); e == nil {
		t.Fatal("addr_parse accepted a malformed address")
	} else {
		cFree(e)
	}
	if h := TailcatClientNew(cbad); h != 0 {
		t.Fatalf("client_new on a malformed address = %d; want 0", h)
	}
	cFree(cbad)
	cempty := cString("{}")
	if e := TailcatKeyPublic(cempty, &nodekey); e == nil {
		t.Fatal("key_public accepted an empty key")
	} else {
		cFree(e)
	}
	cFree(cempty)

	// Close everything and wait for the goroutines to let go.
	check(t, "client_close", cd, TailcatClientClose(cd))
	if rc := TailcatClientClose(cd); rc != cEBADF {
		t.Fatalf("second client_close: rc=%d; want EBADF", rc)
	}
	check(t, "server_close", sd, TailcatServerClose(sd))
	if rc := TailcatServerClose(sd); rc != cEBADF {
		t.Fatalf("second server_close: rc=%d; want EBADF", rc)
	}
	// The server closed the Go end of l80; its C end now reads EOF.
	expectEOF(t, l80)
	syscall.Close(int(l80))

	waitFor(t, "connection and listener cleanup", 5*time.Second, func() bool {
		conns.mu.Lock()
		nc := len(conns.m)
		conns.mu.Unlock()
		listeners.mu.Lock()
		nl := len(listeners.m)
		listeners.mu.Unlock()
		return nc == 0 && nl == 0
	})
	objects.mu.Lock()
	rem := len(objects.m)
	objects.mu.Unlock()
	if rem != 0 {
		t.Fatalf("%d handles remain after close", rem)
	}
}

// TestServerCloseBeforeStart checks that a server that never started can
// be closed, and that its listeners go with it.
func TestServerCloseBeforeStart(t *testing.T) {
	sd := TailcatServerNew()
	check(t, "set_logfd", sd, TailcatSetLogFD(sd, -1))
	var l cInt
	check(t, "listen", sd, TailcatServerListen(sd, 443, &l))
	check(t, "close", sd, TailcatServerClose(sd))
	if rc := TailcatServerClose(sd); rc != cEBADF {
		t.Fatalf("second close: rc=%d; want EBADF", rc)
	}
	if rc := TailcatErrmsg(sd, new(cChar), 1); rc != cEBADF {
		t.Fatalf("errmsg on a closed handle: rc=%d; want EBADF", rc)
	}
	expectEOF(t, l)
	var fd cInt
	if rc := TailcatAccept(l, &fd); rc != cEBADF {
		t.Fatalf("accept on a closed server's listener: rc=%d; want EBADF", rc)
	}
	syscall.Close(int(l))
}

// TestServerConfig checks the configuration calls that need no network.
func TestServerConfig(t *testing.T) {
	sd := TailcatServerNew()
	defer TailcatServerClose(sd)
	_, s := getServer(sd)

	if rc := TailcatServerSetRegionID(sd, -5); rc != -1 {
		t.Fatalf("set_region_id(-5): rc=%d; want -1", rc)
	}
	check(t, "set_region_id", sd, TailcatServerSetRegionID(sd, 302))
	if s.ci.RegionID != 302 {
		t.Fatalf("RegionID = %d; want 302", s.ci.RegionID)
	}
	check(t, "set_region_id auto", sd, TailcatServerSetRegionID(sd, 0))
	if s.ci.RegionID != -1 {
		t.Fatalf("RegionID = %d; want -1 for auto", s.ci.RegionID)
	}
	hosts := cString(" derp1.example.com, derp2.example.com ")
	check(t, "set_relay_hosts", sd, TailcatServerSetRelayHosts(sd, hosts))
	cFree(hosts)
	if len(s.ci.Region) != 1 || len(s.ci.Region[0].Nodes) != 2 || s.ci.Region[0].Nodes[0].HostName != "derp1.example.com" {
		t.Fatalf("relay hosts region = %+v", s.ci.Region)
	}
	empty := cString(",")
	if rc := TailcatServerSetRelayHosts(sd, empty); rc != -1 {
		t.Fatalf("set_relay_hosts(\",\"): rc=%d; want -1", rc)
	}
	cFree(empty)

	// A key file sets the private key and the region.
	pk := tailcat.NewPrivateKey()
	pk.Public.RegionID = 7
	js, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}
	cjs := cString(string(js))
	check(t, "set_key", sd, TailcatServerSetKey(sd, cjs))
	cFree(cjs)
	if !s.priv.Equal(pk.Private) || s.ci.RegionID != 7 || len(s.ci.Region) != 0 {
		t.Fatalf("after set_key: RegionID=%d, Region=%v, key matches=%v", s.ci.RegionID, s.ci.Region, s.priv.Equal(pk.Private))
	}
	if got := readBuf(t, "public_key", sd, func(b *cChar, n cSize) cInt { return TailcatServerPublicKey(sd, b, n) }); got != pk.Private.Public().String() {
		t.Fatalf("public_key = %q; want %q", got, pk.Private.Public().String())
	}
	bad := cString("{}")
	if rc := TailcatServerSetKey(sd, bad); rc != -1 {
		t.Fatalf("set_key(\"{}\"): rc=%d; want -1", rc)
	}
	cFree(bad)
	if rc := TailcatServerAllowClient(sd, bad); rc != -1 {
		t.Fatalf("allow_client(\"{}\"): rc=%d; want -1", rc)
	}
	if rc := TailcatServerListen(sd, 70000, new(cInt)); rc != -1 {
		t.Fatalf("listen(70000): rc=%d; want -1", rc)
	}
	if rc := TailcatServerStart(9999); rc != cEBADF {
		t.Fatalf("start on a bogus handle: rc=%d; want EBADF", rc)
	}
}

// TestClientPublicKeyDoesNotBlock checks that tailcat_client_public_key
// answers right away while another thread's first-use ping is fetching
// the DERP map, instead of waiting behind tailcat's start lock, and that
// the client's key can no longer change once it has been reported.
func TestClientPublicKeyDoesNotBlock(t *testing.T) {
	// A DERP map server that stalls until released, then fails.
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enterOnce.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
		http.Error(w, "no DERP map here", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	// An address that references a DERP map region by ID, so the client
	// must fetch the map, and carries a disco key (the README address
	// predates those, and a client refuses to start without one).
	pk := tailcat.NewPrivateKey()
	pk.Public.RegionID = readmeAddrRegion
	js, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}
	cjs := cString(string(js))
	var keyAddr *cChar
	if e := TailcatKeyAddr(cjs, &keyAddr); e != nil {
		t.Fatalf("key_addr: %s", gostr(e))
	}
	cFree(cjs)
	caddr := cString(gostr(keyAddr))
	defer cFree(caddr)
	cd := TailcatClientNew(caddr)
	if cd == 0 {
		t.Fatal("client_new returned 0 for a key_addr address")
	}
	check(t, "set_logfd", cd, TailcatSetLogFD(cd, -1))
	curl := cString(srv.URL + "/derpmap.json")
	check(t, "set_derpmap_url", cd, TailcatClientSetDERPMapURL(cd, curl))
	cFree(curl)

	pingDone := make(chan cInt, 1)
	go func() { pingDone <- TailcatClientPing(cd, 5000, nil) }()
	select {
	case <-entered:
	case rc := <-pingDone:
		t.Fatalf("the ping returned rc=%d before fetching the DERP map: %s", rc, errmsg(cd))
	case <-time.After(10 * time.Second):
		t.Fatal("the ping never fetched the DERP map")
	}

	start := time.Now()
	pub := readBuf(t, "public_key", cd, func(b *cChar, n cSize) cInt { return TailcatClientPublicKey(cd, b, n) })
	if d := time.Since(start); d > time.Second {
		t.Fatalf("public_key took %v with a ping in flight; want it not to wait for the DERP map fetch", d)
	}
	if !strings.HasPrefix(pub, "nodekey:") {
		t.Fatalf("public_key = %q", pub)
	}
	close(release)
	if rc := <-pingDone; rc != -1 {
		t.Fatalf("ping with no DERP map: rc=%d; want -1", rc)
	}
	t.Logf("ping with no DERP map: %s", errmsg(cd))

	// The key was reported and the client used: set_key is too late.
	other, err := json.Marshal(tailcat.NewPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	cother := cString(string(other))
	if rc := TailcatClientSetKey(cd, cother); rc != -1 {
		t.Fatalf("set_key after use: rc=%d; want -1", rc)
	}
	cFree(cother)
	if got := readBuf(t, "public_key again", cd, func(b *cChar, n cSize) cInt { return TailcatClientPublicKey(cd, b, n) }); got != pub {
		t.Fatalf("public_key changed from %s to %s", pub, got)
	}
	check(t, "client_close", cd, TailcatClientClose(cd))
}
