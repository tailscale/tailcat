// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package perf

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loopback runs a Server on localhost sockets and returns a Client
// dialing it. TCP goes through a real listener. UDP flows are
// emulated with a connected socket on the server side, since that is
// what tailcat's netstack hands the server per client flow.
func loopback(t *testing.T, srv *Server) *Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.HandleTCP(c)
		}
	}()
	return &Client{
		DialTCP: func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		},
		DialUDP: func(ctx context.Context) (net.Conn, error) {
			cc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			sc, err := net.DialUDP("udp", nil, cc.LocalAddr().(*net.UDPAddr))
			if err != nil {
				cc.Close()
				return nil, err
			}
			go srv.HandleUDP(sc)
			return &udpClientConn{UDPConn: cc, peer: sc.LocalAddr()}, nil
		},
	}
}

// udpClientConn makes an unconnected UDP socket look connected to
// peer, so the test's DialUDP can hand out the pair of sockets
// without a race over port numbers.
type udpClientConn struct {
	*net.UDPConn
	peer net.Addr
}

func (c *udpClientConn) Write(b []byte) (int, error) {
	return c.UDPConn.WriteTo(b, c.peer)
}

func (c *udpClientConn) Read(b []byte) (int, error) {
	n, _, err := c.UDPConn.ReadFrom(b)
	return n, err
}

func (c *udpClientConn) RemoteAddr() net.Addr { return c.peer }

func runTest(t *testing.T, p Params) (*Result, *Result) {
	t.Helper()
	var serverRes atomic.Pointer[Result]
	srv := &Server{Logf: t.Logf, OnResult: func(_ net.Addr, res *Result) { serverRes.Store(res) }}
	cl := loopback(t, srv)
	var progress atomic.Int32
	cl.OnProgress = func(Progress) { progress.Add(1) }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cl.Run(ctx, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if p.Interval > 0 && progress.Load() == 0 {
		t.Errorf("no progress callbacks")
	}
	// The server's OnResult may run just after the client returns.
	deadline := time.Now().Add(5 * time.Second)
	for serverRes.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if serverRes.Load() == nil {
		t.Fatal("server never reported a result")
	}
	return res, serverRes.Load()
}

func checkMatch(t *testing.T, what string, sent, received *Stats) {
	t.Helper()
	if sent == nil || received == nil {
		t.Fatalf("%s: sent=%v received=%v; want both", what, sent, received)
	}
	if sent.Bytes == 0 {
		t.Errorf("%s: sent nothing", what)
	}
	if sent.Bytes != received.Bytes {
		t.Errorf("%s: sent %d bytes, received %d", what, sent.Bytes, received.Bytes)
	}
	if sent.Datagrams != received.Datagrams {
		t.Errorf("%s: sent %d datagrams, received %d", what, sent.Datagrams, received.Datagrams)
	}
	if received.Reordered != 0 {
		t.Errorf("%s: %d reordered datagrams on loopback", what, received.Reordered)
	}
	if sent.Duration <= 0 || received.Duration <= 0 {
		t.Errorf("%s: durations sent=%v received=%v; want positive", what, sent.Duration, received.Duration)
	}
}

func TestTCP(t *testing.T) {
	for _, dir := range []Direction{Upload, Download, Bidirectional} {
		t.Run(string(dir), func(t *testing.T) {
			p := Params{Proto: TCP, Direction: dir, Duration: 300 * time.Millisecond, Streams: 2, Length: 64 << 10, Interval: 100 * time.Millisecond}
			res, srvRes := runTest(t, p)
			if dir != Download {
				checkMatch(t, "client to server", res.ClientSent, res.ServerReceived)
				checkMatch(t, "client to server (server view)", srvRes.ClientSent, srvRes.ServerReceived)
			} else if res.ClientSent != nil || res.ServerReceived != nil {
				t.Errorf("download test reported client to server stats")
			}
			if dir != Upload {
				checkMatch(t, "server to client", res.ServerSent, res.ClientReceived)
				checkMatch(t, "server to client (server view)", srvRes.ServerSent, srvRes.ClientReceived)
			} else if res.ServerSent != nil || res.ClientReceived != nil {
				t.Errorf("upload test reported server to client stats")
			}
			if res.RTT == nil || res.RTT.Count == 0 {
				t.Errorf("no RTT samples")
			} else if res.RTT.Min <= 0 || res.RTT.Min > res.RTT.Avg || res.RTT.Avg > res.RTT.Max {
				t.Errorf("RTT stats out of order: %+v", res.RTT)
			}
			if srvRes.RTT != nil {
				t.Errorf("server result has RTT")
			}
			if nIntervals(res.ClientSent)+nIntervals(res.ClientReceived) == 0 {
				t.Errorf("no intervals recorded")
			}
			if nIntervals(res.ServerSent)+nIntervals(res.ServerReceived) != 0 {
				t.Errorf("peer intervals were sent over the wire")
			}
		})
	}
}

// nIntervals returns how many intervals s recorded, treating a nil
// Stats (a direction the test didn't run) as none.
func nIntervals(s *Stats) int {
	if s == nil {
		return 0
	}
	return len(s.Intervals)
}

func TestTCPBytes(t *testing.T) {
	const streams, bytes = 3, 1_000_000
	res, _ := runTest(t, Params{Proto: TCP, Direction: Upload, Bytes: bytes, Streams: streams, Length: 4096})
	if got := res.ServerReceived.Bytes; got != streams*bytes {
		t.Errorf("server received %d bytes; want %d", got, streams*bytes)
	}
}

func TestUDP(t *testing.T) {
	for _, dir := range []Direction{Upload, Download, Bidirectional} {
		t.Run(string(dir), func(t *testing.T) {
			// Paced well below what loopback can carry, so nothing
			// is lost and the counts must match exactly.
			p := Params{Proto: UDP, Direction: dir, Duration: 300 * time.Millisecond, Streams: 2, Length: 200, Bitrate: 2_000_000, Interval: 100 * time.Millisecond}
			res, _ := runTest(t, p)
			if dir != Download {
				checkMatch(t, "client to server", res.ClientSent, res.ServerReceived)
				if res.ClientSent.Datagrams < 10 {
					t.Errorf("only %d datagrams sent", res.ClientSent.Datagrams)
				}
			}
			if dir != Upload {
				checkMatch(t, "server to client", res.ServerSent, res.ClientReceived)
			}
		})
	}
}

func TestUDPBytes(t *testing.T) {
	res, _ := runTest(t, Params{Proto: UDP, Direction: Upload, Bytes: 10_000, Streams: 1, Length: 100})
	if got := res.ServerReceived.Datagrams; got != 100 {
		t.Errorf("server received %d datagrams; want 100", got)
	}
}

func TestServerBusy(t *testing.T) {
	srv := &Server{Logf: t.Logf}
	cl := loopback(t, srv)
	ctx := context.Background()
	p := Params{Proto: TCP, Direction: Upload, Duration: 500 * time.Millisecond, Streams: 1, Length: 4096}

	var wg sync.WaitGroup
	wg.Add(1)
	var firstErr error
	go func() {
		defer wg.Done()
		_, firstErr = cl.Run(ctx, p)
	}()
	// Wait for the first test to be registered.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := len(srv.tests)
		srv.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err := cl.Run(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("second Run error = %v; want busy", err)
	}
	wg.Wait()
	if firstErr != nil {
		t.Errorf("first Run: %v", firstErr)
	}
}

func TestServerLimits(t *testing.T) {
	srv := &Server{MaxStreams: 2, MaxDuration: time.Second}
	cl := loopback(t, srv)
	for _, p := range []Params{
		{Proto: TCP, Direction: Upload, Duration: time.Second, Streams: 3, Length: 4096},
		{Proto: TCP, Direction: Upload, Duration: 2 * time.Second, Streams: 1, Length: 4096},
	} {
		_, err := cl.Run(context.Background(), p)
		if err == nil || !strings.Contains(err.Error(), "server rejected") {
			t.Errorf("Run(%+v) error = %v; want rejection", p, err)
		}
	}
}

func TestValidate(t *testing.T) {
	good := Params{Proto: TCP, Direction: Upload, Duration: time.Second, Streams: 1, Length: 1000}
	if err := good.validate(0, 0); err != nil {
		t.Fatalf("good params rejected: %v", err)
	}
	bad := []func(*Params){
		func(p *Params) { p.Proto = "sctp" },
		func(p *Params) { p.Direction = "sideways" },
		func(p *Params) { p.Duration = 0 },
		func(p *Params) { p.Bytes = -1 },
		func(p *Params) { p.Streams = 0 },
		func(p *Params) { p.Length = 0 },
		func(p *Params) { p.Length = maxLength + 1 },
		func(p *Params) { p.Proto = UDP; p.Length = UDPHeaderLen - 1 },
		func(p *Params) { p.Proto = UDP; p.Length = maxUDPSize + 1 },
		func(p *Params) { p.Bitrate = -1 },
		func(p *Params) { p.Interval = time.Millisecond },
	}
	for i, f := range bad {
		p := good
		f(&p)
		if err := p.validate(0, 0); err == nil {
			t.Errorf("bad params %d accepted: %+v", i, p)
		}
	}
	// Bytes mode needs no duration.
	p := good
	p.Duration = 0
	p.Bytes = 1
	if err := p.validate(0, 0); err != nil {
		t.Errorf("bytes mode rejected: %v", err)
	}
}

func TestUDPHeader(t *testing.T) {
	h := udpHeader{id: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, stream: 513, flags: flagFin, seq: 1 << 40, sendTime: -5}
	buf := make([]byte, UDPHeaderLen)
	h.put(buf)
	got, ok := parseUDPHeader(buf)
	if !ok || got != h {
		t.Errorf("parse(put(%+v)) = %+v, %v", h, got, ok)
	}
	if _, ok := parseUDPHeader(buf[:UDPHeaderLen-1]); ok {
		t.Errorf("short header parsed")
	}
}

// TestJitter feeds a receiver datagrams with synthetic send and
// arrival times and checks the RFC 3550 jitter estimate and the
// reordering count.
func TestJitter(t *testing.T) {
	tt := newTest(Params{Proto: UDP, Streams: 1}, true, nil)
	st := tt.streams[0]
	buf := make([]byte, 100)
	base := time.Unix(1000, 0)
	deliver := func(seq uint64, sent, arrived time.Duration) {
		udpHeader{id: tt.id, seq: seq, sendTime: base.Add(sent).UnixNano()}.put(buf)
		if st.processDatagram(buf, base.Add(arrived)) {
			t.Fatalf("seq %d treated as fin", seq)
		}
	}
	// Constant transit time: no jitter.
	for i := range uint64(10) {
		d := time.Duration(i) * 10 * time.Millisecond
		deliver(i, d, d+50*time.Millisecond)
	}
	if st.jitter != 0 {
		t.Errorf("jitter after constant transit = %v; want 0", time.Duration(st.jitter))
	}
	// Transit alternating by 8ms: the estimate converges toward 8ms.
	for i := uint64(10); i < 200; i++ {
		d := time.Duration(i) * 10 * time.Millisecond
		transit := 50 * time.Millisecond
		if i%2 == 0 {
			transit += 8 * time.Millisecond
		}
		deliver(i, d, d+transit)
	}
	if j := time.Duration(st.jitter); j < 7*time.Millisecond || j > 8*time.Millisecond {
		t.Errorf("jitter after alternating transit = %v; want about 8ms", j)
	}
	// An old sequence number counts as reordered, not as data lost.
	deliver(5, 0, time.Second)
	if st.reordered != 1 {
		t.Errorf("reordered = %d; want 1", st.reordered)
	}
	if st.datagrams != 201 {
		t.Errorf("datagrams = %d; want 201", st.datagrams)
	}
	// Openers and other tests' datagrams are ignored.
	udpHeader{id: tt.id, flags: flagOpen}.put(buf)
	st.processDatagram(buf, base)
	udpHeader{id: [8]byte{9}, seq: 1}.put(buf)
	st.processDatagram(buf, base)
	if st.datagrams != 201 {
		t.Errorf("datagrams after opener and foreign datagram = %d; want 201", st.datagrams)
	}
	udpHeader{id: tt.id, flags: flagFin}.put(buf)
	if !st.processDatagram(buf, base) {
		t.Errorf("fin not recognized")
	}
}

func TestClientContextCancel(t *testing.T) {
	srv := &Server{Logf: t.Logf}
	cl := loopback(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_, err := cl.Run(ctx, Params{Proto: TCP, Direction: Upload, Duration: 10 * time.Second, Streams: 1, Length: 4096})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run error = %v; want context.Canceled", err)
	}
	// The server notices the dropped control connection and frees
	// itself for the next test.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := len(srv.tests)
		srv.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("server still has a registered test after the client went away")
}
