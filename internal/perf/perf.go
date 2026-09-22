// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package perf implements tailcat's throughput and latency test, in
// the style of iperf: a server that sinks and sources bulk TCP and
// UDP traffic, and a client that runs a test against it and gathers
// statistics from both ends.
//
// The client opens a TCP control connection to [Port] and sends a
// hello line with the test parameters. Data then flows on separate
// TCP connections or UDP flows to the same port, one per stream. When
// a side finishes sending it reports what it sent, and when a side
// finishes receiving it reports what it received, both over the
// control connection, so the client ends up with both views of every
// direction. Control messages are JSON lines. UDP datagrams carry a
// small binary header with a sequence number and send timestamp so
// the receiver can count loss and reordering and measure jitter.
// During the test the client also sends pings over the control
// connection to measure round-trip latency while the tunnel is
// loaded.
//
// The server runs one test at a time and rejects others as busy.
package perf

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Port is the TCP and UDP port on the server's tailcat address that
// the perf service uses for its control connection and data streams.
const Port = 5201

// Proto selects the transport a test measures.
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// Direction says which way test data flows, relative to the client.
type Direction string

const (
	Upload        Direction = "up"   // client sends to server
	Download      Direction = "down" // server sends to client
	Bidirectional Direction = "both" // both at once, on the same streams
)

// Params describes a test. The client chooses them and the server
// validates them against its limits.
type Params struct {
	Proto     Proto     `json:"proto"`
	Direction Direction `json:"dir"`

	// Duration is how long each sender sends. It is ignored when
	// Bytes is set.
	Duration time.Duration `json:"duration,omitempty"`

	// Bytes, if non-zero, is how many bytes each stream sends
	// instead of sending for Duration.
	Bytes int64 `json:"bytes,omitempty"`

	// Streams is the number of parallel data connections or flows.
	Streams int `json:"streams"`

	// Length is the size of each TCP write or UDP datagram, in bytes.
	// UDP datagrams include a header of [UDPHeaderLen] bytes.
	Length int `json:"length"`

	// Bitrate, if non-zero, paces each stream's sender to this many
	// bits per second. Zero means send as fast as possible.
	Bitrate int64 `json:"bitrate,omitempty"`

	// Interval is how often to record interval statistics and, on the
	// client, to report progress. Zero disables both.
	Interval time.Duration `json:"interval,omitempty"`
}

// Limits on what a server accepts, and the defaults for the zero
// [Server] fields that set them.
const (
	DefaultMaxStreams  = 128
	DefaultMaxDuration = 10 * time.Minute

	maxLength   = 1 << 20 // largest TCP write
	maxUDPSize  = 65507   // largest UDP datagram
	minInterval = 100 * time.Millisecond
)

// UDPHeaderLen is the size of the header at the start of each UDP
// test datagram, and so the smallest allowed UDP Length.
const UDPHeaderLen = 32

// validate checks p for consistency and, if maxStreams or maxDuration
// are non-zero, against those server limits.
func (p *Params) validate(maxStreams int, maxDuration time.Duration) error {
	switch p.Proto {
	case TCP, UDP:
	default:
		return fmt.Errorf("unknown protocol %q", p.Proto)
	}
	switch p.Direction {
	case Upload, Download, Bidirectional:
	default:
		return fmt.Errorf("unknown direction %q", p.Direction)
	}
	if p.Bytes < 0 {
		return errors.New("negative byte count")
	}
	if p.Bytes == 0 && p.Duration <= 0 {
		return errors.New("a duration or byte count is required")
	}
	if maxDuration > 0 && p.Bytes == 0 && p.Duration > maxDuration {
		return fmt.Errorf("duration %v exceeds the server's limit of %v", p.Duration, maxDuration)
	}
	if p.Streams < 1 {
		return errors.New("at least one stream is required")
	}
	if maxStreams > 0 && p.Streams > maxStreams {
		return fmt.Errorf("%d streams exceeds the server's limit of %d", p.Streams, maxStreams)
	}
	if p.Length < 1 {
		return errors.New("a positive length is required")
	}
	switch p.Proto {
	case TCP:
		if p.Length > maxLength {
			return fmt.Errorf("TCP length %d exceeds %d", p.Length, maxLength)
		}
	case UDP:
		if p.Length < UDPHeaderLen {
			return fmt.Errorf("UDP length %d is smaller than the %d-byte header", p.Length, UDPHeaderLen)
		}
		if p.Length > maxUDPSize {
			return fmt.Errorf("UDP length %d exceeds %d", p.Length, maxUDPSize)
		}
	}
	if p.Bitrate < 0 {
		return errors.New("negative bitrate")
	}
	if p.Interval != 0 && p.Interval < minInterval {
		return fmt.Errorf("interval %v is shorter than %v", p.Interval, minInterval)
	}
	return nil
}

// Stats describes what one side of a test sent or received.
type Stats struct {
	Bytes int64 `json:"bytes"`

	// Datagrams is the number of UDP data datagrams. It is zero for
	// TCP.
	Datagrams int64 `json:"datagrams,omitempty"`

	// Duration is the time from the first to the last byte, as seen
	// by this side.
	Duration time.Duration `json:"duration"`

	// Intervals holds per-interval counts at the test's Interval, for
	// the side that recorded them. It is not sent to the peer.
	Intervals []Interval `json:"intervals,omitempty"`

	// Reordered counts UDP datagrams that arrived with a sequence
	// number lower than one already received. Receivers only.
	Reordered int64 `json:"reordered,omitempty"`

	// Jitter is the RFC 3550 smoothed inter-arrival jitter of UDP
	// datagrams, averaged across streams. Receivers only.
	Jitter time.Duration `json:"jitter,omitempty"`
}

// Interval is the traffic counted during one reporting interval.
type Interval struct {
	Bytes     int64 `json:"bytes"`
	Datagrams int64 `json:"datagrams,omitempty"`
}

// RTT summarizes the control-connection round trips the client
// measured while the test ran.
type RTT struct {
	Min   time.Duration `json:"min"`
	Avg   time.Duration `json:"avg"`
	Max   time.Duration `json:"max"`
	Count int           `json:"count"`
}

// Result is the outcome of a test. Fields for directions the test
// didn't exercise are nil.
type Result struct {
	Params         Params `json:"params"`
	ClientSent     *Stats `json:"clientSent,omitempty"`
	ServerReceived *Stats `json:"serverReceived,omitempty"`
	ServerSent     *Stats `json:"serverSent,omitempty"`
	ClientReceived *Stats `json:"clientReceived,omitempty"`

	// RTT is set on the client's Result if any of its pings during
	// the test were answered, and is nil on the server's.
	RTT *RTT `json:"rtt,omitempty"`
}

// Progress is a client-side snapshot at the end of a reporting
// interval.
type Progress struct {
	Elapsed  time.Duration // since the test started
	Sent     Interval      // during this interval
	Received Interval      // during this interval
	RTT      time.Duration // most recent control round trip, or zero if none yet
}

// Control messages are JSON lines of this type. The TCP data
// connections start with one too, identifying their stream.
type message struct {
	Type   string  `json:"type"`
	Params *Params `json:"params,omitempty"` // hello
	ID     string  `json:"id,omitempty"`     // ok and stream: the test ID in hex
	Stream int     `json:"stream,omitempty"` // stream: which stream this connection is
	Error  string  `json:"error,omitempty"`  // error
	T      int64   `json:"t,omitempty"`      // ping and pong: the pinger's clock, in Unix nanoseconds
	Stats  *Stats  `json:"stats,omitempty"`  // done: the sender's; result: the receiver's
}

const (
	msgHello  = "hello"  // client to server: start a test with Params
	msgOK     = "ok"     // server to client: accepted, with the test ID
	msgError  = "error"  // either way: fatal error
	msgStream = "stream" // first line of a TCP data connection
	msgReady  = "ready"  // server to client: all streams connected, go
	msgPing   = "ping"   // client to server
	msgPong   = "pong"   // server to client
	msgDone   = "done"   // either way: finished sending, with Stats
	msgResult = "result" // either way: finished receiving, with Stats
)

const (
	// handshakeTimeout bounds each step of setting up a test: reading
	// the hello, connecting all the streams, and the client waiting
	// for ready.
	handshakeTimeout = 15 * time.Second

	// reportTimeout bounds how long a side waits for the peer's
	// final done and result messages after finishing its own work.
	reportTimeout = 15 * time.Second

	// The grace periods are how long a receiver keeps reading after
	// the peer says it's done sending, for in-flight data. TCP
	// receivers normally stop at EOF well before this and UDP
	// receivers at the fin datagram, so these only matter when those
	// are lost or delayed.
	tcpGrace = 5 * time.Second
	udpGrace = 2 * time.Second

	// openerInterval is how often the client resends the datagram
	// that opens each UDP flow until the server reports ready.
	openerInterval = 200 * time.Millisecond

	// rttInterval is how often the client pings over the control
	// connection during the test.
	rttInterval = 200 * time.Millisecond

	// ctrlBufSize bounds the length of a control line.
	ctrlBufSize = 64 << 10

	// finRepeat is how many fin datagrams a UDP sender sends, since
	// any one may be lost.
	finRepeat = 3
)

// UDP datagram header layout, all big-endian:
//
//	[0:8]   test ID
//	[8:10]  stream index
//	[10]    flags
//	[11:16] reserved (zero)
//	[16:24] sequence number
//	[24:32] send time, Unix nanoseconds on the sender's clock
const (
	flagOpen = 1 << iota // opens a flow; carries no data
	flagFin              // the sender is done; carries no data
)

type udpHeader struct {
	id       [8]byte
	stream   uint16
	flags    uint8
	seq      uint64
	sendTime int64
}

func (h udpHeader) put(b []byte) {
	copy(b[0:8], h.id[:])
	binary.BigEndian.PutUint16(b[8:10], h.stream)
	b[10] = h.flags
	clear(b[11:16])
	binary.BigEndian.PutUint64(b[16:24], h.seq)
	binary.BigEndian.PutUint64(b[24:32], uint64(h.sendTime))
}

func parseUDPHeader(b []byte) (udpHeader, bool) {
	var h udpHeader
	if len(b) < UDPHeaderLen {
		return h, false
	}
	copy(h.id[:], b[0:8])
	h.stream = binary.BigEndian.Uint16(b[8:10])
	h.flags = b[10]
	h.seq = binary.BigEndian.Uint64(b[16:24])
	h.sendTime = int64(binary.BigEndian.Uint64(b[24:32]))
	return h, true
}

// ctrlConn is a control connection speaking JSON lines.
type ctrlConn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
}

func newCtrlConn(c net.Conn, br *bufio.Reader) *ctrlConn {
	return &ctrlConn{c: c, br: br}
}

func (cc *ctrlConn) send(m *message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	_, err = cc.c.Write(b)
	return err
}

func (cc *ctrlConn) recv() (*message, error) {
	return readMessage(cc.br)
}

// readMessage reads one JSON line. Lines longer than the reader's
// buffer are an error, which bounds what a peer can make us hold.
func readMessage(br *bufio.Reader) (*message, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	m := new(message)
	if err := json.Unmarshal(line, m); err != nil {
		return nil, fmt.Errorf("bad control message: %w", err)
	}
	return m, nil
}

// stripIntervals returns a copy of s without Intervals, for sending
// to the peer.
func stripIntervals(s *Stats) *Stats {
	c := *s
	c.Intervals = nil
	return &c
}

// stream is one data connection or UDP flow of a test.
type stream struct {
	t     *test
	index int

	attached chan struct{} // closed once conn is set
	conn     net.Conn
	rd       io.Reader // where data is read from; conn, or a bufio.Reader that already read the stream header
	pending  []byte    // UDP: the first datagram, read before the receiver started

	// Receiver state, used only by the receiving goroutine.
	firstRecv, lastRecv time.Time
	expectSeq           uint64
	reordered           int64
	jitter              float64 // nanoseconds
	lastTransit         time.Duration
	hasTransit          bool
	datagrams           int64
}

// attach gives the stream its connection. It reports false if the
// stream already had one, in which case the caller should close c.
func (st *stream) attach(c net.Conn, rd io.Reader, pending []byte) bool {
	t := st.t
	t.attachMu.Lock()
	defer t.attachMu.Unlock()
	if st.conn != nil {
		return false
	}
	st.conn = c
	st.rd = rd
	st.pending = pending
	close(st.attached)
	t.nAttached++
	if t.nAttached == len(t.streams) {
		close(t.allAttached)
	}
	return true
}

// test is one running test, on either side.
type test struct {
	p          Params
	id         [8]byte
	isServer   bool
	ctrl       *ctrlConn
	streams    []*stream
	onProgress func(Progress)

	sendBytes, sendDatagrams atomic.Int64
	recvBytes, recvDatagrams atomic.Int64

	attachMu    sync.Mutex
	nAttached   int
	allAttached chan struct{} // closed once every stream has a connection

	ready chan struct{} // client: closed when the server says ready

	peerMu       sync.Mutex
	peerSent     *Stats
	peerReceived *Stats
	peerDone     chan struct{} // closed when the peer's done message arrives
	peerResult   chan struct{} // closed when the peer's result message arrives

	intervalMu    sync.Mutex
	sendIntervals []Interval
	recvIntervals []Interval

	rttMu   sync.Mutex
	rtt     RTT
	rttSum  time.Duration
	lastRTT time.Duration

	sent     *Stats // this side's final sender stats
	received *Stats // this side's final receiver stats

	finishOnce sync.Once
	err        error
	done       chan struct{} // closed when the test finishes or fails
}

func newTest(p Params, isServer bool, ctrl *ctrlConn) *test {
	t := &test{
		p:           p,
		isServer:    isServer,
		ctrl:        ctrl,
		allAttached: make(chan struct{}),
		ready:       make(chan struct{}),
		peerDone:    make(chan struct{}),
		peerResult:  make(chan struct{}),
		done:        make(chan struct{}),
	}
	for i := range p.Streams {
		t.streams = append(t.streams, &stream{t: t, index: i, attached: make(chan struct{})})
	}
	return t
}

// sends reports whether this side sends test data.
func (t *test) sends() bool {
	if t.isServer {
		return t.p.Direction != Upload
	}
	return t.p.Direction != Download
}

// receives reports whether this side receives test data.
func (t *test) receives() bool {
	if t.isServer {
		return t.p.Direction != Download
	}
	return t.p.Direction != Upload
}

// fail ends the test with err, if it hasn't already ended. Closing
// every connection unblocks any goroutine stuck in a read or write.
func (t *test) fail(err error) {
	t.finishOnce.Do(func() {
		t.err = err
		close(t.done)
		t.closeAll()
	})
}

// finish ends the test successfully, if it hasn't already ended.
func (t *test) finish() {
	t.finishOnce.Do(func() {
		close(t.done)
	})
}

func (t *test) closeAll() {
	t.ctrl.c.Close()
	t.attachMu.Lock()
	defer t.attachMu.Unlock()
	for _, st := range t.streams {
		if st.conn != nil {
			st.conn.Close()
		}
	}
}

// ended reports whether the test has finished or failed.
func (t *test) ended() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

// peerIsDone reports whether the peer has said it finished sending.
func (t *test) peerIsDone() bool {
	select {
	case <-t.peerDone:
		return true
	default:
		return false
	}
}

// peerReported reports whether the peer has sent every report this
// side needs from it: its sender stats if it sends, and its receiver
// stats if it receives.
func (t *test) peerReported() bool {
	if t.receives() && !t.peerIsDone() {
		return false
	}
	if t.sends() {
		select {
		case <-t.peerResult:
		default:
			return false
		}
	}
	return true
}

// readControl reads and dispatches control messages until the
// connection closes or the test ends.
func (t *test) readControl() {
	for {
		m, err := t.ctrl.recv()
		if err != nil {
			// Once the peer has sent every report we expect from
			// it, it may close the connection before we notice
			// we're finished.
			if !t.ended() && !t.peerReported() {
				t.fail(fmt.Errorf("control connection: %w", err))
			}
			return
		}
		switch m.Type {
		case msgPing:
			t.ctrl.send(&message{Type: msgPong, T: m.T})
		case msgPong:
			t.recordRTT(time.Since(time.Unix(0, m.T)))
		case msgReady:
			select {
			case <-t.ready:
			default:
				close(t.ready)
			}
		case msgDone:
			t.peerMu.Lock()
			t.peerSent = m.Stats
			t.peerMu.Unlock()
			select {
			case <-t.peerDone:
			default:
				close(t.peerDone)
			}
		case msgResult:
			t.peerMu.Lock()
			t.peerReceived = m.Stats
			t.peerMu.Unlock()
			select {
			case <-t.peerResult:
			default:
				close(t.peerResult)
			}
		case msgError:
			t.fail(fmt.Errorf("peer: %s", m.Error))
			return
		}
	}
}

func (t *test) recordRTT(d time.Duration) {
	t.rttMu.Lock()
	defer t.rttMu.Unlock()
	if t.rtt.Count == 0 || d < t.rtt.Min {
		t.rtt.Min = d
	}
	if d > t.rtt.Max {
		t.rtt.Max = d
	}
	t.rtt.Count++
	t.rttSum += d
	t.rtt.Avg = t.rttSum / time.Duration(t.rtt.Count)
	t.lastRTT = d
}

func (t *test) rttStats() *RTT {
	t.rttMu.Lock()
	defer t.rttMu.Unlock()
	if t.rtt.Count == 0 {
		return nil
	}
	r := t.rtt
	return &r
}

// run performs the test after the handshake and returns its result.
// On the server, all streams must have been created (but not
// necessarily attached) and the ok message sent. On the client, the
// TCP streams must be attached; UDP streams are opened here.
func (t *test) run(ctx context.Context) (*Result, error) {
	defer t.closeAll()
	go t.readControl()
	stop := context.AfterFunc(ctx, func() { t.fail(ctx.Err()) })
	defer stop()

	if err := t.waitReady(); err != nil {
		t.fail(err)
		return nil, t.err
	}

	start := time.Now()
	stopIntervals := t.startIntervals(start)
	var stopPings func()
	if !t.isServer {
		stopPings = t.startPings()
	}

	var wg sync.WaitGroup
	if t.sends() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.runSenders(start)
		}()
	}
	if t.receives() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.runReceivers()
		}()
	}
	wg.Wait()
	stopIntervals()
	if stopPings != nil {
		stopPings()
	}

	// Wait for the peer's view of what it sent and received.
	deadline := time.After(reportTimeout)
	if t.receives() {
		select {
		case <-t.peerDone:
		case <-t.done:
		case <-deadline:
			t.fail(errors.New("timed out waiting for the peer's sender report"))
		}
	}
	if t.sends() {
		select {
		case <-t.peerResult:
		case <-t.done:
		case <-deadline:
			t.fail(errors.New("timed out waiting for the peer's receiver report"))
		}
	}
	t.finish()
	if t.err != nil {
		return nil, t.err
	}

	t.peerMu.Lock()
	defer t.peerMu.Unlock()
	res := &Result{Params: t.p}
	if t.isServer {
		res.ServerSent = t.sent
		res.ServerReceived = t.received
		res.ClientSent = t.peerSent
		res.ClientReceived = t.peerReceived
	} else {
		res.ClientSent = t.sent
		res.ClientReceived = t.received
		res.ServerSent = t.peerSent
		res.ServerReceived = t.peerReceived
		res.RTT = t.rttStats()
	}
	return res, nil
}

// waitReady completes the stream setup: the server waits for every
// stream to connect and then says ready; the client opens its UDP
// flows and waits for ready.
func (t *test) waitReady() error {
	timeout := time.After(handshakeTimeout)
	if t.isServer {
		select {
		case <-t.allAttached:
			return t.ctrl.send(&message{Type: msgReady})
		case <-t.done:
			return t.err
		case <-timeout:
			return errors.New("timed out waiting for the client's streams to connect")
		}
	}

	// The opener datagram that starts each UDP flow is sent
	// repeatedly, since any one may be lost and the server can't
	// send to a flow it hasn't seen.
	var openers *time.Ticker
	if t.p.Proto == UDP {
		if err := t.sendOpeners(); err != nil {
			return err
		}
		openers = time.NewTicker(openerInterval)
		defer openers.Stop()
	}
	for {
		var tick <-chan time.Time
		if openers != nil {
			tick = openers.C
		}
		select {
		case <-t.ready:
			return nil
		case <-t.done:
			return t.err
		case <-timeout:
			return errors.New("timed out waiting for the server to be ready")
		case <-tick:
			if err := t.sendOpeners(); err != nil {
				return err
			}
		}
	}
}

func (t *test) sendOpeners() error {
	var buf [UDPHeaderLen]byte
	for _, st := range t.streams {
		udpHeader{id: t.id, stream: uint16(st.index), flags: flagOpen}.put(buf[:])
		if _, err := st.conn.Write(buf[:]); err != nil {
			return fmt.Errorf("stream %d: opening UDP flow: %w", st.index, err)
		}
	}
	return nil
}

// startIntervals records per-interval counts at the test's Interval
// and, on the client, reports progress. It returns a func that stops
// it.
func (t *test) startIntervals(start time.Time) (stop func()) {
	if t.p.Interval <= 0 {
		return func() {}
	}
	ticker := time.NewTicker(t.p.Interval)
	stopc := make(chan struct{})
	go func() {
		var lastSent, lastRecv Interval
		for {
			var now time.Time
			select {
			case <-stopc:
				return
			case <-t.done:
				return
			case now = <-ticker.C:
			}
			sent := Interval{Bytes: t.sendBytes.Load(), Datagrams: t.sendDatagrams.Load()}
			recv := Interval{Bytes: t.recvBytes.Load(), Datagrams: t.recvDatagrams.Load()}
			dSent := Interval{Bytes: sent.Bytes - lastSent.Bytes, Datagrams: sent.Datagrams - lastSent.Datagrams}
			dRecv := Interval{Bytes: recv.Bytes - lastRecv.Bytes, Datagrams: recv.Datagrams - lastRecv.Datagrams}
			lastSent, lastRecv = sent, recv
			t.intervalMu.Lock()
			if t.sends() {
				t.sendIntervals = append(t.sendIntervals, dSent)
			}
			if t.receives() {
				t.recvIntervals = append(t.recvIntervals, dRecv)
			}
			t.intervalMu.Unlock()
			if t.onProgress != nil {
				t.rttMu.Lock()
				rtt := t.lastRTT
				t.rttMu.Unlock()
				t.onProgress(Progress{Elapsed: now.Sub(start), Sent: dSent, Received: dRecv, RTT: rtt})
			}
		}
	}()
	return func() {
		ticker.Stop()
		close(stopc)
	}
}

// startPings sends periodic pings over the control connection to
// measure round trips under load. It returns a func that stops it.
func (t *test) startPings() (stop func()) {
	ticker := time.NewTicker(rttInterval)
	stopc := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopc:
				return
			case <-t.done:
				return
			case now := <-ticker.C:
				t.ctrl.send(&message{Type: msgPing, T: now.UnixNano()})
			}
		}
	}()
	return func() {
		ticker.Stop()
		close(stopc)
	}
}

func (t *test) snapshotIntervals(send bool) []Interval {
	t.intervalMu.Lock()
	defer t.intervalMu.Unlock()
	if send {
		return t.sendIntervals
	}
	return t.recvIntervals
}

// runSenders sends on every stream, then signals the end of data and
// reports the sender stats to the peer.
func (t *test) runSenders(start time.Time) {
	var wg sync.WaitGroup
	for _, st := range t.streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.sendStream(st, start)
		}()
	}
	wg.Wait()
	if t.ended() {
		return
	}
	stats := &Stats{
		Bytes:     t.sendBytes.Load(),
		Datagrams: t.sendDatagrams.Load(),
		Duration:  time.Since(start),
		Intervals: t.snapshotIntervals(true),
	}
	t.sent = stats
	for _, st := range t.streams {
		if err := t.endStream(st); err != nil {
			t.fail(fmt.Errorf("stream %d: ending: %w", st.index, err))
			return
		}
	}
	if err := t.ctrl.send(&message{Type: msgDone, Stats: stripIntervals(stats)}); err != nil {
		t.fail(fmt.Errorf("sending done: %w", err))
	}
}

// endStream tells the peer that st has no more data: a TCP half-close,
// or fin datagrams for UDP.
func (t *test) endStream(st *stream) error {
	if t.p.Proto == TCP {
		if cw, ok := st.conn.(interface{ CloseWrite() error }); ok {
			return cw.CloseWrite()
		}
		return errors.New("connection can't half-close")
	}
	var buf [UDPHeaderLen]byte
	udpHeader{id: t.id, stream: uint16(st.index), flags: flagFin, sendTime: time.Now().UnixNano()}.put(buf[:])
	for range finRepeat {
		if _, err := st.conn.Write(buf[:]); err != nil {
			return err
		}
	}
	return nil
}

// pacer spaces sends to hold a target bitrate. When it falls behind,
// it sends in a burst to catch up rather than slowing down.
type pacer struct {
	next time.Time
	step time.Duration
}

func newPacer(bitrate int64, length int) *pacer {
	if bitrate <= 0 {
		return nil
	}
	return &pacer{step: time.Duration(float64(length) * 8 / float64(bitrate) * float64(time.Second))}
}

func (p *pacer) wait() {
	now := time.Now()
	if p.next.IsZero() {
		p.next = now
	}
	if d := p.next.Sub(now); d > 0 {
		time.Sleep(d)
	}
	p.next = p.next.Add(p.step)
}

func (t *test) sendStream(st *stream, start time.Time) {
	buf := make([]byte, t.p.Length)
	for i := range buf {
		buf[i] = byte(i)
	}
	pace := newPacer(t.p.Bitrate, t.p.Length)
	var sent int64
	var seq uint64
	for {
		if t.p.Bytes > 0 {
			if sent >= t.p.Bytes {
				return
			}
		} else if time.Since(start) >= t.p.Duration {
			return
		}
		if t.ended() {
			return
		}
		if pace != nil {
			pace.wait()
		}
		n := len(buf)
		if t.p.Proto == UDP {
			udpHeader{id: t.id, stream: uint16(st.index), seq: seq, sendTime: time.Now().UnixNano()}.put(buf)
			seq++
		} else if rem := t.p.Bytes - sent; t.p.Bytes > 0 && rem < int64(n) {
			n = int(rem)
		}
		if _, err := st.conn.Write(buf[:n]); err != nil {
			if !t.ended() {
				t.fail(fmt.Errorf("stream %d: write: %w", st.index, err))
			}
			return
		}
		sent += int64(n)
		t.sendBytes.Add(int64(n))
		if t.p.Proto == UDP {
			t.sendDatagrams.Add(1)
		}
	}
}

// runReceivers reads every stream to its end, then reports the
// receiver stats to the peer.
func (t *test) runReceivers() {
	var wg sync.WaitGroup
	for _, st := range t.streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.recvStream(st)
		}()
	}
	// Once the peer says it's done sending, stop waiting for
	// stragglers after a grace period.
	grace := tcpGrace
	if t.p.Proto == UDP {
		grace = udpGrace
	}
	go func() {
		select {
		case <-t.peerDone:
			deadline := time.Now().Add(grace)
			for _, st := range t.streams {
				st.conn.SetReadDeadline(deadline)
			}
		case <-t.done:
		}
	}()
	wg.Wait()
	if t.ended() {
		return
	}

	stats := &Stats{
		Bytes:     t.recvBytes.Load(),
		Datagrams: t.recvDatagrams.Load(),
		Intervals: t.snapshotIntervals(false),
	}
	var first, last time.Time
	var jitterSum float64
	for _, st := range t.streams {
		if !st.firstRecv.IsZero() && (first.IsZero() || st.firstRecv.Before(first)) {
			first = st.firstRecv
		}
		if st.lastRecv.After(last) {
			last = st.lastRecv
		}
		stats.Reordered += st.reordered
		jitterSum += st.jitter
	}
	if !first.IsZero() {
		stats.Duration = last.Sub(first)
	}
	if t.p.Proto == UDP {
		stats.Jitter = time.Duration(jitterSum / float64(len(t.streams)))
	}
	t.received = stats
	if err := t.ctrl.send(&message{Type: msgResult, Stats: stripIntervals(stats)}); err != nil {
		t.fail(fmt.Errorf("sending result: %w", err))
	}
}

// recvStream reads st until the peer's end of data: EOF for TCP, a
// fin datagram for UDP, or a read error after the peer has said it's
// done (the grace period expiring).
func (t *test) recvStream(st *stream) {
	if t.p.Proto == UDP && st.pending != nil {
		if st.processDatagram(st.pending, time.Now()) {
			return
		}
		st.pending = nil
	}
	buf := make([]byte, max(t.p.Length, 64<<10))
	for {
		n, err := st.rd.Read(buf)
		now := time.Now()
		if n > 0 {
			if t.p.Proto == TCP {
				st.countBytes(n, now)
			} else if st.processDatagram(buf[:n], now) {
				return
			}
		}
		if err != nil {
			if err == io.EOF || t.peerIsDone() || t.ended() {
				return
			}
			t.fail(fmt.Errorf("stream %d: read: %w", st.index, err))
			return
		}
	}
}

func (st *stream) countBytes(n int, now time.Time) {
	if st.firstRecv.IsZero() {
		st.firstRecv = now
	}
	st.lastRecv = now
	st.t.recvBytes.Add(int64(n))
}

// processDatagram accounts for one received datagram and reports
// whether it was a fin. Datagrams that don't belong to this test, and
// openers, are ignored.
func (st *stream) processDatagram(pkt []byte, now time.Time) (fin bool) {
	h, ok := parseUDPHeader(pkt)
	if !ok || h.id != st.t.id {
		return false
	}
	if h.flags&flagFin != 0 {
		return true
	}
	if h.flags&flagOpen != 0 {
		return false
	}
	st.countBytes(len(pkt), now)
	st.t.recvDatagrams.Add(1)
	st.datagrams++
	if h.seq < st.expectSeq {
		st.reordered++
	} else {
		st.expectSeq = h.seq + 1
	}
	// RFC 3550 section 6.4.1 interarrival jitter. The transit time
	// includes the clock offset between the two machines, which
	// cancels out in the difference of successive transits.
	transit := now.Sub(time.Unix(0, h.sendTime))
	if st.hasTransit {
		d := math.Abs(float64(transit - st.lastTransit))
		st.jitter += (d - st.jitter) / 16
	}
	st.lastTransit = transit
	st.hasTransit = true
	return false
}

// Server accepts perf tests. Its zero value is ready to use. Wire
// [Server.HandleTCP] and [Server.HandleUDP] to incoming connections
// and flows on [Port].
type Server struct {
	// Logf, if non-nil, logs failed tests.
	Logf func(format string, args ...any)

	// OnResult, if non-nil, is called with the outcome of each
	// completed test and the client's control connection address.
	OnResult func(remote net.Addr, res *Result)

	// MaxStreams and MaxDuration bound what clients may ask for. Zero
	// means [DefaultMaxStreams] and [DefaultMaxDuration]. A test that
	// sends a byte count instead of a duration is cut off at
	// MaxDuration regardless.
	MaxStreams  int
	MaxDuration time.Duration

	mu    sync.Mutex
	tests map[[8]byte]*test // the running test, if any
}

func (s *Server) maxStreams() int {
	if s.MaxStreams > 0 {
		return s.MaxStreams
	}
	return DefaultMaxStreams
}

func (s *Server) maxDuration() time.Duration {
	if s.MaxDuration > 0 {
		return s.MaxDuration
	}
	return DefaultMaxDuration
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// register makes t the running test, reporting false if another test
// is already running.
func (s *Server) register(t *test) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tests) > 0 {
		return false
	}
	if s.tests == nil {
		s.tests = map[[8]byte]*test{}
	}
	s.tests[t.id] = t
	return true
}

func (s *Server) unregister(t *test) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tests, t.id)
}

// lookupStream finds the stream a data connection or flow belongs to.
func (s *Server) lookupStream(id [8]byte, index int) (*test, *stream, error) {
	s.mu.Lock()
	t := s.tests[id]
	s.mu.Unlock()
	if t == nil {
		return nil, nil, errors.New("unknown test")
	}
	if index < 0 || index >= len(t.streams) {
		return nil, nil, fmt.Errorf("stream index %d out of range", index)
	}
	return t, t.streams[index], nil
}

// HandleTCP serves one incoming TCP connection to [Port], which is
// either a control connection starting a test or a data stream of a
// running test. It returns when the test ends and closes c.
func (s *Server) HandleTCP(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, ctrlBufSize)
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	m, err := readMessage(br)
	if err != nil {
		s.logf("perf: %v: reading first message: %v", c.RemoteAddr(), err)
		return
	}
	c.SetReadDeadline(time.Time{})
	switch m.Type {
	case msgHello:
		s.runTest(c, br, m)
	case msgStream:
		var id [8]byte
		b, err := hex.DecodeString(m.ID)
		if err != nil || len(b) != len(id) {
			return
		}
		copy(id[:], b)
		t, st, err := s.lookupStream(id, m.Stream)
		if err != nil {
			s.logf("perf: %v: data connection: %v", c.RemoteAddr(), err)
			return
		}
		if !st.attach(c, br, nil) {
			return
		}
		<-t.done
	}
}

// HandleUDP serves one incoming UDP flow to [Port], a data stream of
// a running test. Each Read of c must return one datagram. It returns
// when the test ends and closes c.
func (s *Server) HandleUDP(c net.Conn) {
	defer c.Close()
	buf := make([]byte, maxUDPSize)
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	h, ok := parseUDPHeader(buf[:n])
	if !ok {
		return
	}
	t, st, err := s.lookupStream(h.id, int(h.stream))
	if err != nil {
		s.logf("perf: %v: UDP flow: %v", c.RemoteAddr(), err)
		return
	}
	if !st.attach(c, c, buf[:n:n]) {
		return
	}
	<-t.done
}

// runTest runs a test whose control connection just sent hello.
func (s *Server) runTest(c net.Conn, br *bufio.Reader, hello *message) {
	ctrl := newCtrlConn(c, br)
	if hello.Params == nil {
		ctrl.send(&message{Type: msgError, Error: "hello without params"})
		return
	}
	p := *hello.Params
	if err := p.validate(s.maxStreams(), s.maxDuration()); err != nil {
		ctrl.send(&message{Type: msgError, Error: err.Error()})
		return
	}
	t := newTest(p, true, ctrl)
	if _, err := rand.Read(t.id[:]); err != nil {
		ctrl.send(&message{Type: msgError, Error: "server error"})
		return
	}
	if !s.register(t) {
		ctrl.send(&message{Type: msgError, Error: "the server is busy with another test"})
		return
	}
	defer s.unregister(t)
	if err := ctrl.send(&message{Type: msgOK, ID: hex.EncodeToString(t.id[:])}); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.maxDuration()+handshakeTimeout+reportTimeout)
	defer cancel()
	res, err := t.run(ctx)
	if err != nil {
		s.logf("perf: test from %v failed: %v", c.RemoteAddr(), err)
		return
	}
	if s.OnResult != nil {
		s.OnResult(c.RemoteAddr(), res)
	}
}

// Client runs tests against a server.
type Client struct {
	// DialTCP opens a TCP connection to the server's [Port].
	DialTCP func(ctx context.Context) (net.Conn, error)

	// DialUDP opens a UDP flow to the server's [Port]. Each Read of
	// the returned conn must return one datagram. It is only needed
	// for UDP tests.
	DialUDP func(ctx context.Context) (net.Conn, error)

	// OnProgress, if non-nil, is called at the end of each reporting
	// interval of a test with a non-zero Interval.
	OnProgress func(Progress)
}

// Run runs one test and returns its result. It returns an error if
// the server rejects the parameters, is busy, or the test fails.
func (c *Client) Run(ctx context.Context, p Params) (*Result, error) {
	if err := p.validate(0, 0); err != nil {
		return nil, err
	}
	if p.Proto == UDP && c.DialUDP == nil {
		return nil, errors.New("perf: Client.DialUDP is required for UDP tests")
	}
	cc, err := c.DialTCP(ctx)
	if err != nil {
		return nil, fmt.Errorf("dialing control connection: %w", err)
	}
	ctrl := newCtrlConn(cc, bufio.NewReaderSize(cc, ctrlBufSize))
	t := newTest(p, false, ctrl)
	t.onProgress = c.OnProgress
	// Until run takes over, closing the streams on error is our job.
	ok := false
	defer func() {
		if !ok {
			t.closeAll()
		}
	}()

	if err := ctrl.send(&message{Type: msgHello, Params: &p}); err != nil {
		return nil, fmt.Errorf("sending hello: %w", err)
	}
	cc.SetReadDeadline(time.Now().Add(handshakeTimeout))
	m, err := ctrl.recv()
	if err != nil {
		return nil, fmt.Errorf("reading hello reply: %w", err)
	}
	cc.SetReadDeadline(time.Time{})
	switch m.Type {
	case msgError:
		return nil, fmt.Errorf("server rejected the test: %s", m.Error)
	case msgOK:
	default:
		return nil, fmt.Errorf("unexpected reply %q to hello", m.Type)
	}
	id, err := hex.DecodeString(m.ID)
	if err != nil || len(id) != len(t.id) {
		return nil, errors.New("server sent a malformed test ID")
	}
	copy(t.id[:], id)

	for _, st := range t.streams {
		var dc net.Conn
		if p.Proto == TCP {
			dc, err = c.DialTCP(ctx)
			if err != nil {
				return nil, fmt.Errorf("dialing stream %d: %w", st.index, err)
			}
			hdr, _ := json.Marshal(&message{Type: msgStream, ID: m.ID, Stream: st.index})
			if _, err := dc.Write(append(hdr, '\n')); err != nil {
				dc.Close()
				return nil, fmt.Errorf("stream %d: sending header: %w", st.index, err)
			}
		} else {
			dc, err = c.DialUDP(ctx)
			if err != nil {
				return nil, fmt.Errorf("dialing UDP stream %d: %w", st.index, err)
			}
		}
		st.attach(dc, dc, nil)
	}
	ok = true
	return t.run(ctx)
}
