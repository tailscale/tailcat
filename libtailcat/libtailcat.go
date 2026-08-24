// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// A Go c-archive of the tailcat package. See tailcat.h for details.
package main

//#include <errno.h>
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {}

// handles tracks all the allocated server and client objects. The
// values are *tcServer or *tcClient. Handle values start well above
// the range of plausible file descriptors so that mixing one up with
// an fd fails fast.
var handles struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]any
}

func newHandle(v any) C.int {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	if handles.m == nil {
		handles.m = map[C.int]any{}
		handles.next = 42<<16 + 1
	}
	h := handles.next
	handles.next++
	handles.m[h] = v
	return h
}

func getServer(h C.int) *tcServer {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	s, _ := handles.m[h].(*tcServer)
	return s
}

func getClient(h C.int) *tcClient {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	c, _ := handles.m[h].(*tcClient)
	return c
}

// getState returns the common state of the server or client handle h,
// or nil if h is not a valid handle.
func getState(h C.int) *handleState {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	switch v := handles.m[h].(type) {
	case *tcServer:
		return &v.handleState
	case *tcClient:
		return &v.handleState
	}
	return nil
}

func deleteHandle(h C.int) any {
	handles.mu.Lock()
	defer handles.mu.Unlock()
	v := handles.m[h]
	delete(handles.m, h)
	return v
}

// handleState is the state common to server and client handles: the
// last error message and the event queue.
type handleState struct {
	errMu   sync.Mutex
	lastErr string

	ev events
}

func (h *handleState) recErr(err error) C.int {
	h.errMu.Lock()
	defer h.errMu.Unlock()
	if err == nil {
		h.lastErr = ""
		return 0
	}
	h.lastErr = err.Error()
	return -1
}

// events is a queue of pending JSON-encoded events plus a socketpair
// whose C-visible end becomes readable when events are queued. Bytes
// on the socketpair are wakeup hints only, not exact event counts;
// after draining them, C should call tailcat_event_next until it
// returns EAGAIN.
type events struct {
	mu    sync.Mutex
	queue []string
	goFD  int   // Go writes wakeup hint bytes here (nonblocking)
	cFD   C.int // C reads hint bytes here
}

func (e *events) init() error {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	if err := syscall.SetNonblock(fds[1], true); err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return err
	}
	e.cFD = C.int(fds[0])
	e.goFD = fds[1]
	return nil
}

func (e *events) enqueue(v map[string]any) {
	j, err := json.Marshal(v)
	if err != nil {
		panic(err) // events are built from marshalable types above
	}
	e.mu.Lock()
	e.queue = append(e.queue, string(j))
	e.mu.Unlock()
	// Best effort: if the buffer is full (C isn't reading), earlier
	// unread hint bytes already mark the fd readable.
	syscall.Write(e.goFD, []byte{0})
}

// close closes the Go side of the event socketpair, which makes the C
// side readable with EOF: the signal that the handle was closed.
func (e *events) close() {
	syscall.Close(e.goFD)
}

// tcServer is the state behind a tailcat_server handle.
type tcServer struct {
	handleState

	mu         sync.Mutex
	priv       key.NodePrivate
	derpmapURL string
	regionID   int
	logf       logger.Logf
	srv        *tailcat.Server
	blob       tailcat.ConnBlob
	started    bool

	// portsMu guards ports. It is separate from mu because the OnTCP
	// dispatcher consults ports from netstack while Start may be
	// holding mu.
	portsMu sync.Mutex
	ports   map[uint16]*listener
}

func (s *tcServer) logfSafe() logger.Logf {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logf
}

// tcClient is the state behind a tailcat_client handle.
type tcClient struct {
	handleState

	cl   *tailcat.Client
	done chan struct{} // closed by TailcatClientClose

	mu   sync.Mutex
	logf logger.Logf
}

// parsePrivateKey parses the text form of a node private key
// ("privkey:..."), as produced by TailcatKeypairNew. A nil or empty
// string generates a new key.
func parsePrivateKey(cstr *C.char) (key.NodePrivate, error) {
	var priv key.NodePrivate
	if cstr == nil || *cstr == 0 {
		return key.NewNode(), nil
	}
	if err := priv.UnmarshalText([]byte(C.GoString(cstr))); err != nil {
		return priv, err
	}
	return priv, nil
}

// copyOut copies s into the C buffer buf of size buflen,
// NUL-terminating it. It returns 0 or ERANGE if s doesn't fit.
func copyOut(s string, buf *C.char, buflen C.size_t) C.int {
	if buf == nil || buflen == 0 {
		panic("nil or empty output buffer")
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	n := copy(out, s)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TailcatKeypairNew
func TailcatKeypairNew(buf *C.char, buflen C.size_t) C.int {
	priv := key.NewNode()
	txt, err := priv.MarshalText()
	if err != nil {
		return -1
	}
	return copyOut(string(txt), buf, buflen)
}

//export TailcatPubkey
func TailcatPubkey(privkey *C.char, buf *C.char, buflen C.size_t) C.int {
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(C.GoString(privkey))); err != nil {
		copyOut("", buf, buflen)
		return -1
	}
	return copyOut(priv.Public().String(), buf, buflen)
}

//export TailcatServerNew
func TailcatServerNew(privkey *C.char) C.int {
	priv, err := parsePrivateKey(privkey)
	if err != nil {
		return 0
	}
	s := &tcServer{
		priv:     priv,
		regionID: -1, // auto-select by latency
		logf:     logger.Discard,
	}
	if err := s.ev.init(); err != nil {
		return 0
	}
	return newHandle(s)
}

//export TailcatServerSetDerpmapURL
func TailcatServerSetDerpmapURL(h C.int, url *C.char) C.int {
	s := getServer(h)
	if s == nil {
		return C.EBADF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.derpmapURL = C.GoString(url)
	return 0
}

//export TailcatServerSetRegionID
func TailcatServerSetRegionID(h C.int, regionID C.int) C.int {
	s := getServer(h)
	if s == nil {
		return C.EBADF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.regionID = int(regionID)
	return 0
}

//export TailcatServerSetLogFD
func TailcatServerSetLogFD(h, fd C.int) C.int {
	s := getServer(h)
	if s == nil {
		return C.EBADF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logf = logfForFD(fd)
	return 0
}

func logfForFD(fd C.int) logger.Logf {
	if fd == -1 {
		return logger.Discard
	}
	f := os.NewFile(uintptr(fd), "logfd")
	return func(format string, args ...any) {
		fmt.Fprintf(f, format, args...)
		fmt.Fprintf(f, "\n")
	}
}

//export TailcatServerStart
func TailcatServerStart(h C.int) C.int {
	s := getServer(h)
	if s == nil {
		return C.EBADF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return s.recErr(fmt.Errorf("libtailcat: server already started"))
	}

	ci := &tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: s.priv.Public()},
		RegionID:     s.regionID,
	}
	opts := []any{tailcat.ExpandForServer}
	if s.derpmapURL != "" {
		opts = append(opts, tailcat.DERPMapURL(s.derpmapURL))
	}
	if err := ci.Expand(context.Background(), opts...); err != nil {
		return s.recErr(err)
	}
	if len(ci.Region) == 0 {
		return s.recErr(fmt.Errorf("libtailcat: no DERP region resolved"))
	}
	reg := ci.Region[0]

	// The blob references the relay region by ID; clients resolve it
	// from their own DERP map URL.
	s.blob = (&tailcat.ConnInfo{
		ServerPublic: ci.ServerPublic,
		RegionID:     reg.RegionID,
	}).ConnBlob()

	srv, err := tailcat.NewServer(s.priv, s.logf, reg)
	if err != nil {
		return s.recErr(err)
	}
	srv.OnTCP = func(port uint16) func(net.Conn) {
		s.portsMu.Lock()
		l := s.ports[port]
		s.portsMu.Unlock()
		if l == nil {
			return nil // RST
		}
		return l.handle
	}
	srv.OnClientConnect = func(k key.NodePublic) {
		s.ev.enqueue(map[string]any{
			"type": "client-connected",
			"key":  k.String(),
		})
	}
	if err := srv.Start(); err != nil {
		return s.recErr(err)
	}
	// Wait for the relay connection so that clients given the
	// ConnBlob right after this returns can reach us immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.WaitDERPConnected(ctx); err != nil {
		srv.Close()
		return s.recErr(fmt.Errorf("waiting for relay connection: %w", err))
	}
	s.srv = srv
	s.started = true
	return 0
}

//export TailcatServerConnblob
func TailcatServerConnblob(h C.int, buf *C.char, buflen C.size_t) C.int {
	s := getServer(h)
	if s == nil {
		copyOut("", buf, buflen)
		return C.EBADF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		copyOut("", buf, buflen)
		return s.recErr(fmt.Errorf("libtailcat: server not started"))
	}
	return copyOut(string(s.blob), buf, buflen)
}

// listeners tracks all the listener socketpairs allocated via
// TailcatServerListen, keyed by the fd given to C.
var listeners struct {
	mu sync.Mutex
	m  map[C.int]*listener
}

// listener accepts connections for one TCP port of a server. It is
// one side of a socketpair: accepted connection fds are passed to the
// C side via SCM_RIGHTS, so the C side can epoll its end to learn
// when a connection is ready to accept.
type listener struct {
	s    *tcServer
	port uint16
	fd   int   // Go side of the socketpair
	cFD  C.int // C side of the socketpair
}

//export TailcatServerListen
func TailcatServerListen(h C.int, port C.int, listenerOut *C.int) C.int {
	s := getServer(h)
	if s == nil {
		return C.EBADF
	}
	if port < 0 || port > 65535 {
		return s.recErr(fmt.Errorf("libtailcat: invalid port %d", port))
	}

	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return s.recErr(err)
	}
	l := &listener{s: s, port: uint16(port), fd: fds[1], cFD: C.int(fds[0])}

	s.portsMu.Lock()
	if _, dup := s.ports[uint16(port)]; dup {
		s.portsMu.Unlock()
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return s.recErr(fmt.Errorf("libtailcat: port %d already has a listener", port))
	}
	if s.ports == nil {
		s.ports = map[uint16]*listener{}
	}
	s.ports[uint16(port)] = l
	s.portsMu.Unlock()

	listeners.mu.Lock()
	if listeners.m == nil {
		listeners.m = map[C.int]*listener{}
	}
	listeners.m[l.cFD] = l
	listeners.mu.Unlock()

	go func() {
		// The C side never writes, so this read blocks until C closes
		// its end of the socketpair: the signal to tear down.
		var buf [16]byte
		syscall.Read(l.fd, buf[:])
		l.close()
	}()

	*listenerOut = l.cFD
	return 0
}

// close tears down the listener, removing it from its server's port
// map and the global listener map. It is safe to call twice: the fd
// is closed only by whichever call removes it from the map.
func (l *listener) close() {
	l.s.portsMu.Lock()
	if l.s.ports[l.port] == l {
		delete(l.s.ports, l.port)
	}
	l.s.portsMu.Unlock()

	listeners.mu.Lock()
	cur, ok := listeners.m[l.cFD]
	if ok && cur == l {
		delete(listeners.m, l.cFD)
		syscall.Close(l.fd)
	}
	listeners.mu.Unlock()
}

// handle is the tailcat OnTCP handler for one accepted connection on
// this listener's port: it wraps the connection in a socketpair and
// passes the C-side fd through the listener socketpair via SCM_RIGHTS
// for TailcatAccept (or the C caller's own recvmsg) to pick up.
func (l *listener) handle(netConn net.Conn) {
	c, connFD, err := newConn()
	if err != nil {
		l.s.logfSafe()("libtailcat: newConn: %v", err)
		netConn.Close()
		return
	}
	// One byte of real data accompanies the rights; SOCK_STREAM
	// ancillary data is not reliably delivered with zero-length
	// messages, and the byte also marks the fd readable for poll.
	rights := syscall.UnixRights(int(connFD))
	if err := syscall.Sendmsg(l.fd, []byte{0}, rights, nil, 0); err != nil {
		l.s.logfSafe()("libtailcat: sendmsg: %v", err)
		netConn.Close()
		c.cleanup()
		syscall.Close(int(connFD))
		return
	}
	syscall.Close(int(connFD)) // now owned by the recvmsg side
	c.start(netConn)
}

//export TailcatAccept
func TailcatAccept(listenerFD C.int, connOut *C.int) C.int {
	listeners.mu.Lock()
	l := listeners.m[listenerFD]
	listeners.mu.Unlock()
	if l == nil {
		return C.EBADF
	}

	data := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := syscall.Recvmsg(int(listenerFD), data, oob, 0)
	if err != nil {
		return l.s.recErr(err)
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return l.s.recErr(err)
	}
	if len(scms) != 1 {
		return l.s.recErr(fmt.Errorf("libtailcat: got %d control messages, want 1", len(scms)))
	}
	fds, err := syscall.ParseUnixRights(&scms[0])
	if err != nil {
		return l.s.recErr(err)
	}
	if len(fds) != 1 {
		return l.s.recErr(fmt.Errorf("libtailcat: got %d fds, want 1", len(fds)))
	}
	*connOut = C.int(fds[0])
	return 0
}

//export TailcatServerClose
func TailcatServerClose(h C.int) C.int {
	v := deleteHandle(h)
	s, ok := v.(*tcServer)
	if !ok {
		return C.EBADF
	}

	s.portsMu.Lock()
	ls := make([]*listener, 0, len(s.ports))
	for _, l := range s.ports {
		ls = append(ls, l)
	}
	s.portsMu.Unlock()

	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()

	for _, l := range ls {
		l.close()
	}
	s.ev.close()
	if srv != nil {
		if err := srv.Close(); err != nil {
			return -1
		}
	}
	return 0
}

//export TailcatClientNew
func TailcatClientNew(connblob, privkey *C.char) C.int {
	priv, err := parsePrivateKey(privkey)
	if err != nil {
		return 0
	}
	c := &tcClient{
		logf: logger.Discard,
		done: make(chan struct{}),
	}
	// Indirect logf so TailcatClientSetLogFD works after creation.
	logf := func(format string, args ...any) {
		c.mu.Lock()
		f := c.logf
		c.mu.Unlock()
		f(format, args...)
	}
	cl, err := tailcat.NewClient(logf, tailcat.ConnBlob(C.GoString(connblob)), priv)
	if err != nil {
		return 0
	}
	if err := c.ev.init(); err != nil {
		cl.Close()
		return 0
	}
	c.cl = cl
	go func() {
		select {
		case <-cl.Connected():
			c.ev.enqueue(map[string]any{"type": "connected"})
		case <-c.done:
		}
	}()
	return newHandle(c)
}

//export TailcatClientSetDerpmapURL
func TailcatClientSetDerpmapURL(h C.int, url *C.char) C.int {
	c := getClient(h)
	if c == nil {
		return C.EBADF
	}
	c.cl.DERPMapURL = C.GoString(url)
	return 0
}

//export TailcatClientSetLogFD
func TailcatClientSetLogFD(h, fd C.int) C.int {
	c := getClient(h)
	if c == nil {
		return C.EBADF
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logf = logfForFD(fd)
	return 0
}

//export TailcatClientConnect
func TailcatClientConnect(h C.int, latencyMsOut *C.double) C.int {
	c := getClient(h)
	if c == nil {
		return C.EBADF
	}
	res, err := c.cl.Ping(context.Background())
	if err != nil {
		return c.recErr(err)
	}
	if latencyMsOut != nil {
		*latencyMsOut = C.double(res.Latency.Seconds() * 1e3)
	}
	return 0
}

// dialTimeout bounds a TailcatClientDial tunnel establishment plus
// TCP connect. The meow handshake inside it has its own 10s cap.
const dialTimeout = 30 * time.Second

//export TailcatClientDial
func TailcatClientDial(h C.int, port C.int, connOut *C.int) C.int {
	c := getClient(h)
	if c == nil {
		return C.EBADF
	}
	if port < 0 || port > 65535 {
		return c.recErr(fmt.Errorf("libtailcat: invalid port %d", port))
	}

	conn, connFD, err := newConn()
	if err != nil {
		return c.recErr(err)
	}
	// The fd is valid (and safe to epoll or write to) immediately;
	// writes buffer in the socketpair until the dial completes. Set
	// the out param before the goroutine can emit events naming it.
	*connOut = connFD

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		netConn, err := c.cl.DialTCPPort(ctx, uint16(port))
		if err != nil {
			// Closing the Go side gives the C side EOF on read.
			conn.cleanup()
			c.ev.enqueue(map[string]any{
				"type": "dial-error",
				"conn": int(connFD),
				"err":  err.Error(),
			})
			return
		}
		conn.start(netConn)
		c.ev.enqueue(map[string]any{
			"type": "dial-ok",
			"conn": int(connFD),
		})
	}()
	return 0
}

//export TailcatClientClose
func TailcatClientClose(h C.int) C.int {
	v := deleteHandle(h)
	c, ok := v.(*tcClient)
	if !ok {
		return C.EBADF
	}
	close(c.done)
	c.ev.close()
	if err := c.cl.Close(); err != nil {
		return -1
	}
	return 0
}

//export TailcatEventsFD
func TailcatEventsFD(h C.int) C.int {
	st := getState(h)
	if st == nil {
		// Not EBADF: that's a plausible fd number.
		return -1
	}
	return st.ev.cFD
}

//export TailcatEventNext
func TailcatEventNext(h C.int, buf *C.char, buflen C.size_t) C.int {
	st := getState(h)
	if st == nil {
		copyOut("", buf, buflen)
		return C.EBADF
	}
	st.ev.mu.Lock()
	defer st.ev.mu.Unlock()
	if len(st.ev.queue) == 0 {
		copyOut("", buf, buflen)
		return C.EAGAIN
	}
	// Pop only if it fits, so a caller getting ERANGE can retry with
	// a bigger buffer without losing the event.
	if ret := copyOut(st.ev.queue[0], buf, buflen); ret != 0 {
		return ret
	}
	st.ev.queue = st.ev.queue[1:]
	return 0
}

//export TailcatErrmsg
func TailcatErrmsg(h C.int, buf *C.char, buflen C.size_t) C.int {
	st := getState(h)
	if st == nil {
		copyOut("", buf, buflen)
		return C.EBADF
	}
	st.errMu.Lock()
	defer st.errMu.Unlock()
	return copyOut(st.lastErr, buf, buflen)
}

// conns tracks all live connection socketpairs, for leak detection in
// tests and to make teardown idempotent.
var conns struct {
	mu sync.Mutex
	m  map[*conn]bool
}

// conn shuttles bytes between a tailcat net.Conn and the socketpair
// whose far end was handed to C.
type conn struct {
	r *os.File // Go side of the socketpair

	mu sync.Mutex
	c  net.Conn // nil until start
}

// newConn allocates the socketpair for a connection and registers it.
// The returned fd is the C side. Pumping starts when start is called
// with the tailcat connection; until then, C-side writes accumulate
// in the socketpair buffer.
func newConn() (*conn, C.int, error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, 0, err
	}
	c := &conn{r: os.NewFile(uintptr(fds[1]), "socketpair-r")}
	conns.mu.Lock()
	if conns.m == nil {
		conns.m = map[*conn]bool{}
	}
	conns.m[c] = true
	conns.mu.Unlock()
	return c, C.int(fds[0]), nil
}

// start begins copying between netConn and the socketpair, in both
// directions. When one direction finishes, its half-close is
// propagated (shutdown on the socketpair, CloseRead/CloseWrite on the
// tailcat side) but the other direction keeps flowing, so netcat-style
// protocols that FIN one way and then read the response work. Full
// teardown happens only once both directions are done.
func (c *conn) start(netConn net.Conn) {
	c.mu.Lock()
	c.c = netConn
	c.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var b [1 << 16]byte
		io.CopyBuffer(c.r, netConn, b[:])
		syscall.Shutdown(int(c.r.Fd()), syscall.SHUT_WR)
		if cr, ok := netConn.(interface{ CloseRead() error }); ok {
			cr.CloseRead()
		}
	}()
	go func() {
		defer wg.Done()
		var b [1 << 16]byte
		io.CopyBuffer(netConn, c.r, b[:])
		syscall.Shutdown(int(c.r.Fd()), syscall.SHUT_RD)
		if cw, ok := netConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		wg.Wait()
		c.cleanup()
	}()
}

// cleanup closes the Go side of the conn. It is safe to call multiple
// times; only the call that removes the conn from the registry closes
// anything.
func (c *conn) cleanup() {
	conns.mu.Lock()
	registered := conns.m[c]
	delete(conns.m, c)
	conns.mu.Unlock()
	if !registered {
		return
	}
	c.r.Close()
	c.mu.Lock()
	netConn := c.c
	c.mu.Unlock()
	if netConn != nil {
		netConn.Close()
	}
}
