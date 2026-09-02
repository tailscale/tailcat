// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

// Command libtailcat is the Go side of the libtailcat C library, built
// with -buildmode=c-archive. See include/tailcat.h for the C API and
// tailcat.c for the shim that maps each tailcat_* function to the
// TailcatXxx function exported here.
//
// The design follows libtailscale (github.com/tailscale/libtailscale):
// handles are small integers in a process-wide table; every connection
// handed to C is one end of a socketpair(2) that goroutines pump to and
// from the tunnel connection; and a listener is a socketpair over which
// accepted connections are passed to C as descriptors with SCM_RIGHTS.
package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include <errno.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/tailscale/tailcat"
	"golang.org/x/sys/unix"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {}

var (
	errServerStarted = errors.New("server already started")
	errServerClosed  = errors.New("server closed")
	errNotStarted    = errors.New("server not started")
	errClientStarted = errors.New("client already started; set options before its first use")
	errClientClosed  = errors.New("client closed")
	errKeyFixed      = errors.New("client key already generated; set the key before asking for the public key")
)

// objects is the handle table: every tailcat_handle given to C maps to a
// server or a client. Handles start well above any plausible descriptor
// number so the two can't be confused.
var objects struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]*object
}

// object is what a tailcat_handle refers to. Exactly one of s and c is
// non-nil.
type object struct {
	s *server
	c *client

	mu      sync.Mutex
	lastErr string
}

// recErr records err as the object's last error, for tailcat_errmsg, and
// returns the C result code for it.
func (o *object) recErr(err error) C.int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil {
		o.lastErr = ""
		return 0
	}
	o.lastErr = err.Error()
	return -1
}

func (o *object) errmsg() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastErr
}

func newHandle(o *object) C.int {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	if objects.m == nil {
		objects.m = map[C.int]*object{}
	}
	if objects.next == 0 {
		objects.next = 42<<16 + 1
	}
	h := objects.next
	objects.next++
	objects.m[h] = o
	return h
}

func getObject(h C.int) *object {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	return objects.m[h]
}

// getServer returns the server behind h, or nil if h is not a live server
// handle (a client handle counts as invalid here).
func getServer(h C.int) (*object, *server) {
	o := getObject(h)
	if o == nil || o.s == nil {
		return nil, nil
	}
	return o, o.s
}

// getClient is getServer for clients.
func getClient(h C.int) (*object, *client) {
	o := getObject(h)
	if o == nil || o.c == nil {
		return nil, nil
	}
	return o, o.c
}

// takeObject removes h from the handle table for closing, returning nil
// if h isn't a live handle of the requested kind.
func takeObject(h C.int, wantServer bool) *object {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	o := objects.m[h]
	if o == nil || (wantServer && o.s == nil) || (!wantServer && o.c == nil) {
		return nil
	}
	delete(objects.m, h)
	return o
}

// checkBuf panics on a nil or empty output buffer, which the C API
// documents as a programming error, so that every other path can leave
// the buffer NUL-terminated.
func checkBuf(fn string, buf *C.char, buflen C.size_t) {
	if buf == nil {
		panic(fn + " passed nil buf")
	} else if buflen == 0 {
		panic(fn + " passed buflen of 0")
	}
}

// cstrOut copies s into the C buffer buf of buflen bytes, always
// NUL-terminating it, and reports ERANGE if s didn't fit whole.
func cstrOut(buf *C.char, buflen C.size_t, s string) C.int {
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	n := copy(out, s)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

// cerr returns err as a malloc'd C string, or NULL for nil, the
// convention of the handle-free key and token functions.
func cerr(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

// timeoutContext returns a context that expires after timeoutMs
// milliseconds, or one with no deadline when timeoutMs is zero or less.
func timeoutContext(timeoutMs C.int) (context.Context, context.CancelFunc) {
	if timeoutMs <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
}

//export TailcatErrmsg
func TailcatErrmsg(h C.int, buf *C.char, buflen C.size_t) C.int {
	checkBuf("errmsg", buf, buflen)
	o := getObject(h)
	if o == nil {
		*buf = '\x00'
		return C.EBADF
	}
	return cstrOut(buf, buflen, o.errmsg())
}

//export TailcatSetLogFD
func TailcatSetLogFD(h, fd C.int) C.int {
	o := getObject(h)
	if o == nil {
		return C.EBADF
	}
	logf := logfForFD(int(fd))
	if o.s != nil {
		return o.s.configure(func() error {
			o.s.logf = logf
			return nil
		})
	}
	return o.c.configure(func() error {
		o.c.cl.Logf = logf
		return nil
	})
}

// logfForFD returns a logger writing one line per message to the caller's
// descriptor fd, or one discarding everything for -1. The descriptor stays
// the caller's: it is written with plain write(2) calls and never wrapped
// in an os.File, whose finalizer would close it behind the caller's back.
func logfForFD(fd int) logger.Logf {
	if fd == -1 {
		return logger.Discard
	}
	var mu sync.Mutex
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if !strings.HasSuffix(msg, "\n") {
			msg += "\n"
		}
		mu.Lock()
		defer mu.Unlock()
		b := []byte(msg)
		for len(b) > 0 {
			n, err := syscall.Write(fd, b)
			if err == syscall.EINTR {
				continue
			}
			if err != nil || n <= 0 {
				return
			}
			b = b[n:]
		}
	}
}

// server is the state behind a server handle: configuration until start,
// then the running tailcat.Server and its listeners.
type server struct {
	obj *object

	mu         sync.Mutex
	priv       key.NodePrivate      // zero until first needed
	ci         tailcat.ConnInfo     // where to listen; RegionID -1 means auto
	derpMapURL string               // "" means tailcat.DefaultDERPMapURL
	embed      bool                 // token embeds the relay details
	allowed    []key.NodePublic     // allowed clients, in order of addition
	logf       logger.Logf          // nil means log.Printf
	ports      map[uint16]*listener // by port; 0 is the catch-all
	testRegion *tailcfg.DERPRegion  // set by setServerRegionForTest
	starting   bool                 // a start is in progress
	srv        *tailcat.Server      // non-nil once started
	token      tailcat.ConnBlob     // valid once started
	closed     bool
}

// logfOr returns the server's logger, defaulting to log.Printf like
// tailcat.Server does.
func (s *server) logfOr() logger.Logf {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.logf != nil {
		return s.logf
	}
	return log.Printf
}

// privLocked returns the server's private key, generating one on first
// use. s.mu must be held.
func (s *server) privLocked() key.NodePrivate {
	if s.priv.IsZero() {
		s.priv = key.NewNode()
	}
	return s.priv
}

// configure runs f with s.mu held, refusing once the server has started
// or is starting, since the settings f changes are read at start.
func (s *server) configure(f func() error) C.int {
	s.mu.Lock()
	var err error
	switch {
	case s.closed:
		err = errServerClosed
	case s.starting || s.srv != nil:
		err = errServerStarted
	default:
		err = f()
	}
	s.mu.Unlock()
	return s.obj.recErr(err)
}

// parsePrivateKey decodes the JSON of a tailcat.PrivateKey, the format of
// "tailcat genkey" key files.
func parsePrivateKey(js string) (*tailcat.PrivateKey, error) {
	pk := new(tailcat.PrivateKey)
	if err := json.Unmarshal([]byte(js), pk); err != nil {
		return nil, fmt.Errorf("parsing key JSON: %w", err)
	}
	if pk.Private.IsZero() {
		return nil, errors.New("key JSON has no Private key")
	}
	return pk, nil
}

//export TailcatServerNew
func TailcatServerNew() C.int {
	o := &object{}
	o.s = &server{obj: o, ci: tailcat.ConnInfo{RegionID: -1}}
	return newHandle(o)
}

//export TailcatServerSetKey
func TailcatServerSetKey(sd C.int, keyJSON *C.char) C.int {
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	pk, err := parsePrivateKey(C.GoString(keyJSON))
	if err != nil {
		return o.recErr(err)
	}
	return s.configure(func() error {
		s.priv = pk.Private
		s.ci = tailcat.ConnInfo{RegionID: pk.Public.RegionID, Region: pk.Public.Region}
		if s.ci.RegionID == 0 && len(s.ci.Region) == 0 {
			// A client key (genkey --client) carries no region; pick
			// one automatically rather than failing at start.
			s.ci.RegionID = -1
		}
		return nil
	})
}

//export TailcatServerSetRegionID
func TailcatServerSetRegionID(sd C.int, regionID C.int) C.int {
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if regionID < 0 {
		return o.recErr(fmt.Errorf("invalid DERP region ID %d", regionID))
	}
	return s.configure(func() error {
		s.ci.Region = nil
		s.ci.RegionID = tailcfg.DERPRegionID(regionID)
		if regionID == 0 {
			s.ci.RegionID = -1 // auto
		}
		return nil
	})
}

//export TailcatServerSetRelayHosts
func TailcatServerSetRelayHosts(sd C.int, hosts *C.char) C.int {
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	// Like "tailcat genkey --region=<host,...>": a region with no DERP
	// map ID whose nodes are just hostnames. Expand fills in the rest.
	reg := &tailcfg.DERPRegion{}
	for _, h := range strings.Split(C.GoString(hosts), ",") {
		if h = strings.TrimSpace(h); h != "" {
			reg.Nodes = append(reg.Nodes, &tailcfg.DERPNode{HostName: h})
		}
	}
	if len(reg.Nodes) == 0 {
		return o.recErr(errors.New("no relay hosts given"))
	}
	return s.configure(func() error {
		s.ci.Region = []*tailcfg.DERPRegion{reg}
		s.ci.RegionID = 0
		return nil
	})
}

//export TailcatServerSetDERPMapURL
func TailcatServerSetDERPMapURL(sd C.int, url *C.char) C.int {
	_, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	u := C.GoString(url)
	return s.configure(func() error {
		s.derpMapURL = u
		return nil
	})
}

//export TailcatServerSetEmbedRelay
func TailcatServerSetEmbedRelay(sd C.int, embed C.int) C.int {
	_, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	return s.configure(func() error {
		s.embed = embed != 0
		return nil
	})
}

//export TailcatServerAllowClient
func TailcatServerAllowClient(sd C.int, nodekey *C.char) C.int {
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(C.GoString(nodekey))); err != nil {
		return o.recErr(fmt.Errorf("invalid node key: %w", err))
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return o.recErr(errServerClosed)
	}
	// Keys added before start are passed to the Server at start; keys
	// added while a start is in progress are applied when it finishes
	// (see start); keys added after go straight to the Server.
	s.allowed = append(s.allowed, k)
	srv := s.srv
	s.mu.Unlock()
	if srv != nil {
		srv.AddAllowedClient(k)
	}
	return o.recErr(nil)
}

//export TailcatServerListen
func TailcatServerListen(sd C.int, port C.int, listenerOut *C.int) C.int {
	if listenerOut == nil {
		panic("server_listen passed nil listener_out")
	}
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if port < 0 || port > 65535 {
		return o.recErr(fmt.Errorf("invalid port %d", port))
	}
	ln, err := s.listen(uint16(port))
	if err != nil {
		return o.recErr(err)
	}
	*listenerOut = ln.fdC
	return o.recErr(nil)
}

//export TailcatServerStart
func TailcatServerStart(sd C.int) C.int {
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	return o.recErr(s.start())
}

// start resolves the DERP region and starts the tailcat.Server, holding
// s.mu only around the state transitions, never across the network work.
func (s *server) start() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errServerClosed
	}
	if s.starting || s.srv != nil {
		s.mu.Unlock()
		return errServerStarted
	}
	s.starting = true
	priv := s.privLocked()
	ci := s.ci
	// A pre-populated region (relay hosts, from set_relay_hosts or the
	// key) has no DERP map ID to reference, so its token always embeds
	// the relay. Decide before Expand, which zeroes RegionID when it
	// populates Region.
	embed := s.embed || len(ci.Region) > 0
	if s.testRegion != nil {
		ci = tailcat.ConnInfo{Region: []*tailcfg.DERPRegion{s.testRegion.Clone()}}
		embed = true
	}
	url := s.derpMapURL
	logf := s.logf
	allowed := slices.Clone(s.allowed)
	nAllowed := len(s.allowed)
	s.mu.Unlock()

	srv, token, err := startServer(priv, ci, embed, url, logf, allowed, s.dispatch)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.starting = false
	if err != nil {
		return err
	}
	if s.closed {
		srv.Close()
		return errServerClosed
	}
	s.srv = srv
	s.token = token
	// Keys allowed while the start was in progress.
	for _, k := range s.allowed[nAllowed:] {
		srv.AddAllowedClient(k)
	}
	return nil
}

// startServer mirrors the tailcat CLI's server start sequence
// (cmd/tailcat/tailcat.go, func server): expand ci into a DERP region,
// trim the region to what's needed, build the token, and start the
// server. The token is built here rather than with Server.ConnBlob, which
// always embeds the full region, so that the short form (a DERP map
// region ID) is available.
func startServer(priv key.NodePrivate, ci tailcat.ConnInfo, embed bool, derpMapURL string, logf logger.Logf, allowed []key.NodePublic, onTCP func(uint16) func(net.Conn)) (*tailcat.Server, tailcat.ConnBlob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := []any{tailcat.ExpandForServer}
	if derpMapURL != "" {
		opts = append(opts, tailcat.DERPMapURL(derpMapURL))
	}
	if err := ci.Expand(ctx, opts...); err != nil {
		return nil, "", fmt.Errorf("resolving DERP region: %w", err)
	}
	if len(ci.Region) == 0 {
		return nil, "", errors.New("no DERP region resolved")
	}
	// Work on a copy: the region may belong to the caller (the test hook)
	// or be shared with the ConnInfo kept for a retried start.
	reg := ci.Region[0].Clone()
	clearUnnecessaryRegionFields(reg)

	tok := tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: priv.Public()},
		ServerDiscoPublic: tailcat.DiscoPublicForNode(priv),
	}
	if embed {
		tok.Region = []*tailcfg.DERPRegion{reg}
	} else {
		tok.RegionID = reg.RegionID
	}
	token := tok.ConnBlob()

	srv := &tailcat.Server{
		Key:            priv,
		Logf:           logf,
		Region:         reg,
		AllowedClients: allowed,
		OnTCP:          onTCP,
	}
	if err := srv.Start(); err != nil {
		return nil, "", err
	}
	return srv, token, nil
}

// clearUnnecessaryRegionFields is copied from the tailcat CLI: it drops
// the parts of a DERP map region that neither the server nor the token
// needs, keeping a single relay node so both sides use the same one.
func clearUnnecessaryRegionFields(r *tailcfg.DERPRegion) {
	r.Latitude = 0
	r.Longitude = 0
	r.RegionCode = ""
	if len(r.Nodes) > 1 {
		r.Nodes = r.Nodes[:1]
	}
	for _, n := range r.Nodes {
		n.CanPort80 = false
		n.RegionID = 0
	}
}

// setServerRegionForTest makes the server at sd listen on reg without
// fetching a DERP map, embedding reg in its token, so tests can run
// against an in-process DERP server. Call it before start.
func setServerRegionForTest(sd C.int, reg *tailcfg.DERPRegion) {
	_, s := getServer(sd)
	if s == nil {
		panic("setServerRegionForTest: not a server handle")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.testRegion = reg
}

// dispatch is the Server.OnTCP callback. It is installed once at start
// and consults the port table on every connection, so listeners
// registered after start are honored too. Ports with no listener and no
// catch-all get a nil handler, which the server answers with a RST.
func (s *server) dispatch(port uint16) func(net.Conn) {
	s.mu.Lock()
	ln := s.ports[port]
	if ln == nil {
		ln = s.ports[0]
	}
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return func(nc net.Conn) { ln.handoff(nc, port) }
}

//export TailcatServerToken
func TailcatServerToken(sd C.int, buf *C.char, buflen C.size_t) C.int {
	checkBuf("server_token", buf, buflen)
	o, s := getServer(sd)
	if s == nil {
		*buf = '\x00'
		return C.EBADF
	}
	s.mu.Lock()
	token := s.token
	started := s.srv != nil
	s.mu.Unlock()
	if !started {
		*buf = '\x00'
		return o.recErr(errNotStarted)
	}
	return cstrOut(buf, buflen, string(token))
}

//export TailcatServerPublicKey
func TailcatServerPublicKey(sd C.int, buf *C.char, buflen C.size_t) C.int {
	checkBuf("server_public_key", buf, buflen)
	_, s := getServer(sd)
	if s == nil {
		*buf = '\x00'
		return C.EBADF
	}
	s.mu.Lock()
	pub := s.privLocked().Public()
	s.mu.Unlock()
	return cstrOut(buf, buflen, pub.String())
}

//export TailcatServerStatusJSON
func TailcatServerStatusJSON(sd C.int, jsonOut **C.char) C.int {
	if jsonOut == nil {
		panic("server_status_json passed nil json_out")
	}
	*jsonOut = nil
	o, s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return o.recErr(errNotStarted)
	}
	b, err := json.Marshal(srv.Status())
	if err != nil {
		return o.recErr(err)
	}
	*jsonOut = C.CString(string(b))
	return o.recErr(nil)
}

//export TailcatServerClose
func TailcatServerClose(sd C.int) C.int {
	o := takeObject(sd, true)
	if o == nil {
		return C.EBADF
	}
	s := o.s
	s.mu.Lock()
	s.closed = true
	srv := s.srv
	s.srv = nil
	var lns []*listener
	for _, ln := range s.ports {
		lns = append(lns, ln)
	}
	s.ports = nil
	s.mu.Unlock()

	// Close the Go ends first so C-side reads see EOF right away, then
	// the server itself. A start in progress finds s.closed set and
	// closes the server it built.
	for _, ln := range lns {
		ln.cleanup()
	}
	closeConnsOf(o)
	if srv != nil {
		if err := srv.Close(); err != nil {
			s.logfOr()("libtailcat: server close: %v", err)
			return -1
		}
	}
	return 0
}

// listeners tracks every listener by the descriptor C holds, the
// tailcat_listener value.
var listeners struct {
	mu sync.Mutex
	m  map[C.int]*listener
}

// listener is a registered port. Accepted connections are passed to C over
// a socketpair: the Go end sends each connection's descriptor with
// SCM_RIGHTS, and C receives it with tailcat_accept.
type listener struct {
	s    *server
	port uint16
	f    *os.File // the Go end of the socketpair, pollable
	fdC  C.int    // the C end, the tailcat_listener value

	sendMu sync.Mutex // serializes handoff messages so each is sent whole

	mu sync.Mutex
	m  map[C.int]accepted // by the descriptor tailcat_accept returned

	closeOnce sync.Once
}

// accepted is what tailcat_conn_info reports for an accepted connection.
type accepted struct {
	remote    string
	localPort uint16
}

// listen registers a listener for port, or fails if the port has one.
func (s *server) listen(port uint16) (*listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errServerClosed
	}
	if old := s.ports[port]; old != nil {
		// C may have just closed old's descriptor, in which case old's
		// watch goroutine is about to unregister the port. Look at the
		// socketpair directly so an immediate re-listen doesn't race it.
		if !peerClosed(old.f) {
			return nil, fmt.Errorf("port %d already has a listener", port)
		}
		delete(s.ports, port)
	}

	// The tailcat_listener we return to C is one side of a socketpair(2).
	// Connections are pushed through it as they arrive, so C can poll(2)
	// the listener to learn when tailcat_accept won't block.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	setNoSigPipe(fds[0])
	setNoSigPipe(fds[1])
	if err := syscall.SetNonblock(fds[1], true); err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return nil, err
	}
	ln := &listener{
		s:    s,
		port: port,
		f:    os.NewFile(uintptr(fds[1]), "tailcat-listener"),
		fdC:  C.int(fds[0]),
	}
	if s.ports == nil {
		s.ports = map[uint16]*listener{}
	}
	s.ports[port] = ln

	listeners.mu.Lock()
	if listeners.m == nil {
		listeners.m = map[C.int]*listener{}
	}
	listeners.m[ln.fdC] = ln
	listeners.mu.Unlock()

	go ln.watch()
	return ln, nil
}

// watch blocks until C closes its end of the socketpair. C never writes
// to its end, so a read only returns at EOF, or when the Go end is closed
// by tailcat_server_close. Either way the listener is then torn down.
func (ln *listener) watch() {
	var buf [256]byte
	for {
		if _, err := ln.f.Read(buf[:]); err != nil {
			break
		}
	}
	ln.cleanup()
}

// cleanup unregisters the listener and closes its Go end. It runs once,
// whether triggered by C closing the listener or by the server closing.
func (ln *listener) cleanup() {
	ln.closeOnce.Do(func() {
		// The descriptor number may already have been reused by a newer
		// listener, so only remove entries that are still ours.
		listeners.mu.Lock()
		if listeners.m[ln.fdC] == ln {
			delete(listeners.m, ln.fdC)
		}
		listeners.mu.Unlock()

		s := ln.s
		s.mu.Lock()
		if s.ports[ln.port] == ln {
			delete(s.ports, ln.port)
		}
		s.mu.Unlock()

		ln.f.Close()
	})
}

// A handoff message announces one accepted connection to tailcat_accept.
// It is fixed-size so that a recvmsg of exactly handoffLen bytes reads one
// message, and the connection's descriptor rides on its first byte as
// SCM_RIGHTS. Layout: local port (2 bytes, big endian), remote address
// length (1 byte), remote address, zero padding.
const handoffLen = 64

// handoff wraps an accepted tunnel connection to port in a socketpair and
// sends C's end through the listener.
func (ln *listener) handoff(nc net.Conn, port uint16) {
	remote := nc.RemoteAddr().String()
	c, cfd, err := newConn(ln.s.obj, nc)
	if err != nil {
		ln.s.logfOr()("libtailcat: accepting a connection on port %d: %v", port, err)
		nc.Close()
		return
	}
	msg := make([]byte, handoffLen)
	binary.BigEndian.PutUint16(msg[0:2], port)
	if max := handoffLen - 3; len(remote) > max {
		remote = remote[:max]
	}
	msg[2] = byte(len(remote))
	copy(msg[3:], remote)

	ln.sendMu.Lock()
	err = sendHandoff(ln.f, msg, syscall.UnixRights(cfd))
	ln.sendMu.Unlock()
	syscall.Close(cfd) // C gets its own descriptor from recvmsg
	if err != nil {
		// The listener is closed (C closed it, or the server did).
		ln.s.logfOr()("libtailcat: handing off a connection on port %d: %v", port, err)
		c.cleanup()
	}
}

// sendHandoff sends msg over the pollable socket f with rights attached to
// its first byte, waiting for buffer space as needed. Only trailing bytes
// can be left by a short send, and they carry no rights.
func sendHandoff(f *os.File, msg, rights []byte) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	for sent := 0; sent < len(msg); {
		oob := rights
		if sent > 0 {
			oob = nil
		}
		var n int
		var serr error
		if err := rc.Write(func(fd uintptr) bool {
			n, serr = syscall.SendmsgN(int(fd), msg[sent:], oob, nil, 0)
			return serr != syscall.EAGAIN && serr != syscall.EWOULDBLOCK && serr != syscall.EINTR
		}); err != nil {
			return err
		}
		if serr != nil {
			return serr
		}
		sent += n
	}
	return nil
}

// recvHandoff reads one handoff message from C's listener descriptor lfd,
// returning the connection descriptor it carried and the message.
func recvHandoff(lfd int) (connFd int, msg []byte, err error) {
	msg = make([]byte, handoffLen)
	oob := make([]byte, unix.CmsgSpace(4))
	connFd = -1
	for got := 0; got < handoffLen; {
		var o []byte
		if got == 0 {
			o = oob // the rights ride on the first byte
		}
		n, oobn, _, _, err := syscall.Recvmsg(lfd, msg[got:], o, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return -1, nil, err
		}
		if n == 0 {
			return -1, nil, errors.New("listener closed")
		}
		if oobn > 0 {
			scms, err := syscall.ParseSocketControlMessage(o[:oobn])
			if err != nil {
				return -1, nil, err
			}
			if len(scms) != 1 {
				return -1, nil, fmt.Errorf("libtailcat: got %d control messages, want 1", len(scms))
			}
			fds, err := syscall.ParseUnixRights(&scms[0])
			if err != nil {
				return -1, nil, err
			}
			if len(fds) != 1 {
				for _, fd := range fds {
					syscall.Close(fd)
				}
				return -1, nil, fmt.Errorf("libtailcat: got %d descriptors, want 1", len(fds))
			}
			connFd = fds[0]
		}
		got += n
	}
	if connFd < 0 {
		return -1, nil, errors.New("libtailcat: handoff message carried no descriptor")
	}
	return connFd, msg, nil
}

//export TailcatAccept
func TailcatAccept(l C.int, connOut *C.int) C.int {
	if connOut == nil {
		panic("accept passed nil conn_out")
	}
	listeners.mu.Lock()
	ln := listeners.m[l]
	listeners.mu.Unlock()
	if ln == nil {
		return C.EBADF
	}
	o := ln.s.obj

	fd, msg, err := recvHandoff(int(l))
	if err != nil {
		return o.recErr(err)
	}
	info := accepted{
		localPort: binary.BigEndian.Uint16(msg[0:2]),
		remote:    string(msg[3 : 3+int(msg[2])]),
	}
	ln.mu.Lock()
	if ln.m == nil {
		ln.m = map[C.int]accepted{}
	}
	ln.m[C.int(fd)] = info
	ln.mu.Unlock()

	*connOut = C.int(fd)
	return o.recErr(nil)
}

//export TailcatConnInfo
func TailcatConnInfo(l, c C.int, remoteBuf *C.char, remoteBuflen C.size_t, localPortOut *C.int) C.int {
	checkBuf("conn_info", remoteBuf, remoteBuflen)
	listeners.mu.Lock()
	ln := listeners.m[l]
	listeners.mu.Unlock()
	if ln == nil {
		*remoteBuf = '\x00'
		return C.EBADF
	}
	ln.mu.Lock()
	info, ok := ln.m[c]
	ln.mu.Unlock()
	if !ok {
		*remoteBuf = '\x00'
		return C.EBADF
	}
	if localPortOut != nil {
		*localPortOut = C.int(info.localPort)
	}
	return cstrOut(remoteBuf, remoteBuflen, info.remote)
}

// conns tracks every connection handed to C, for closing them along with
// their server or client.
var conns struct {
	mu sync.Mutex
	m  map[*conn]struct{}
}

// conn is a connection handed to C: one end of a socketpair went to C,
// the other, r, is pumped to and from the tunnel connection by two
// goroutines, one per direction. Each direction propagates its EOF as a
// half-close, and the connection is torn down once both directions are
// done, as soon as C closes its descriptor entirely, or when the owning
// server or client closes.
type conn struct {
	owner   *object
	netConn net.Conn
	r       *os.File // the Go end of the socketpair, pollable
	once    sync.Once
}

// newConn wraps the tunnel connection nc in a socketpair, returning the
// conn and the descriptor for C.
func newConn(owner *object, nc net.Conn) (*conn, int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, -1, err
	}
	setNoSigPipe(fds[0])
	setNoSigPipe(fds[1])
	// Non-blocking so that os.File uses the runtime poller: goroutines
	// blocked on r are woken by r.Close, which a plain blocking read of a
	// closed descriptor would not be.
	if err := syscall.SetNonblock(fds[1], true); err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return nil, -1, err
	}
	c := &conn{owner: owner, netConn: nc, r: os.NewFile(uintptr(fds[1]), "tailcat-conn")}

	conns.mu.Lock()
	if conns.m == nil {
		conns.m = map[*conn]struct{}{}
	}
	conns.m[c] = struct{}{}
	conns.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		// Tunnel to C. The peer's EOF becomes a write shutdown of C's
		// end: C's reads return 0 while its writes still flow.
		defer wg.Done()
		var b [1 << 16]byte
		io.CopyBuffer(c.r, nc, b[:])
		shutdown(c.r, syscall.SHUT_WR)
		if cr, ok := nc.(interface{ CloseRead() error }); ok {
			cr.CloseRead()
		}
	}()
	go func() {
		// C to tunnel. EOF from C is either shutdown(SHUT_WR), which
		// becomes a half-close of the tunnel connection, or close(2),
		// after which nothing can reach C anymore, so the connection is
		// torn down right away instead of waiting for the peer.
		defer wg.Done()
		var b [1 << 16]byte
		io.CopyBuffer(nc, c.r, b[:])
		if peerClosed(c.r) {
			c.cleanup()
			return
		}
		shutdown(c.r, syscall.SHUT_RD)
		if cw, ok := nc.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			nc.Close()
		}
	}()
	go func() {
		wg.Wait()
		c.cleanup()
	}()
	return c, fds[0], nil
}

// cleanup closes both sides of the connection. It runs once.
func (c *conn) cleanup() {
	c.once.Do(func() {
		conns.mu.Lock()
		delete(conns.m, c)
		conns.mu.Unlock()
		c.r.Close()
		c.netConn.Close()
	})
}

// closeConnsOf tears down every connection owned by o.
func closeConnsOf(o *object) {
	conns.mu.Lock()
	var list []*conn
	for c := range conns.m {
		if c.owner == o {
			list = append(list, c)
		}
	}
	conns.mu.Unlock()
	for _, c := range list {
		c.cleanup()
	}
}

// shutdown calls shutdown(2) on the pollable file f without taking it out
// of non-blocking mode, as f.Fd would.
func shutdown(f *os.File, how int) {
	rc, err := f.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) { syscall.Shutdown(int(fd), how) })
}

// peerClosed reports whether the other end of the socketpair behind f has
// been closed outright, as opposed to shut down for writing: poll(2)
// reports POLLHUP for a closed peer and just POLLOUT for a half-closed one
// (true on Darwin and Linux), which is how the Go side tells close(2) from
// shutdown(SHUT_WR) on the C side once its reads hit EOF. A closed f
// counts as closed.
func peerClosed(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return true
	}
	closed := true
	if err := rc.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		for {
			n, err := unix.Poll(fds, 0)
			if err == syscall.EINTR {
				continue
			}
			closed = err != nil || (n > 0 && fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0)
			return
		}
	}); err != nil {
		return true
	}
	return closed
}

// client is the state behind a client handle.
type client struct {
	obj *object

	mu       sync.Mutex
	cl       *tailcat.Client
	keyFixed bool // the key has been read or generated; set_key is too late
	started  bool // the first ping, path or dial has happened
	closed   bool
}

// configure runs f with c.mu held, refusing once the client has been
// used, since tailcat.Client reads its options at first use.
func (c *client) configure(f func() error) C.int {
	c.mu.Lock()
	var err error
	switch {
	case c.closed:
		err = errClientClosed
	case c.started:
		err = errClientStarted
	default:
		err = f()
	}
	c.mu.Unlock()
	return c.obj.recErr(err)
}

// use marks the client as started and returns the tailcat.Client to call.
func (c *client) use() (*tailcat.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errClientClosed
	}
	c.started = true
	c.keyFixed = true
	return c.cl, nil
}

//export TailcatClientNew
func TailcatClientNew(token *C.char) C.int {
	blob := tailcat.ConnBlob(C.GoString(token))
	if _, err := tailcat.ParseConnBlob(blob); err != nil {
		return 0
	}
	o := &object{}
	o.c = &client{obj: o, cl: &tailcat.Client{Server: blob}}
	return newHandle(o)
}

//export TailcatClientSetKey
func TailcatClientSetKey(cd C.int, keyJSON *C.char) C.int {
	o, c := getClient(cd)
	if c == nil {
		return C.EBADF
	}
	pk, err := parsePrivateKey(C.GoString(keyJSON))
	if err != nil {
		return o.recErr(err)
	}
	return c.configure(func() error {
		if c.keyFixed {
			return errKeyFixed
		}
		c.cl.Key = pk.Private
		return nil
	})
}

//export TailcatClientSetDERPMapURL
func TailcatClientSetDERPMapURL(cd C.int, url *C.char) C.int {
	_, c := getClient(cd)
	if c == nil {
		return C.EBADF
	}
	u := C.GoString(url)
	return c.configure(func() error {
		c.cl.DERPMapURL = u
		return nil
	})
}

//export TailcatClientPublicKey
func TailcatClientPublicKey(cd C.int, buf *C.char, buflen C.size_t) C.int {
	checkBuf("client_public_key", buf, buflen)
	_, c := getClient(cd)
	if c == nil {
		*buf = '\x00'
		return C.EBADF
	}
	c.mu.Lock()
	c.keyFixed = true // PublicKey generates and pins the ephemeral key
	pub := c.cl.PublicKey()
	c.mu.Unlock()
	return cstrOut(buf, buflen, pub.String())
}

//export TailcatClientPing
func TailcatClientPing(cd C.int, timeoutMs C.int, latencyMsOut *C.double) C.int {
	o, c := getClient(cd)
	if c == nil {
		return C.EBADF
	}
	cl, err := c.use()
	if err != nil {
		return o.recErr(err)
	}
	ctx, cancel := timeoutContext(timeoutMs)
	defer cancel()
	res, err := cl.Ping(ctx)
	if err != nil {
		return o.recErr(err)
	}
	if latencyMsOut != nil {
		*latencyMsOut = C.double(float64(res.Latency) / float64(time.Millisecond))
	}
	return o.recErr(nil)
}

//export TailcatClientPathJSON
func TailcatClientPathJSON(cd C.int, timeoutMs C.int, jsonOut **C.char) C.int {
	if jsonOut == nil {
		panic("client_path_json passed nil json_out")
	}
	*jsonOut = nil
	o, c := getClient(cd)
	if c == nil {
		return C.EBADF
	}
	cl, err := c.use()
	if err != nil {
		return o.recErr(err)
	}
	ctx, cancel := timeoutContext(timeoutMs)
	defer cancel()
	res, err := cl.DiscoPing(ctx)
	if err != nil {
		return o.recErr(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		return o.recErr(err)
	}
	*jsonOut = C.CString(string(b))
	return o.recErr(nil)
}

//export TailcatClientDial
func TailcatClientDial(cd C.int, port C.int, timeoutMs C.int, connOut *C.int) C.int {
	if connOut == nil {
		panic("client_dial passed nil conn_out")
	}
	o, c := getClient(cd)
	if c == nil {
		return C.EBADF
	}
	if port < 1 || port > 65535 {
		return o.recErr(fmt.Errorf("invalid port %d", port))
	}
	cl, err := c.use()
	if err != nil {
		return o.recErr(err)
	}
	ctx, cancel := timeoutContext(timeoutMs)
	defer cancel()
	nc, err := cl.DialTCPPort(ctx, uint16(port))
	if err != nil {
		return o.recErr(err)
	}
	_, cfd, err := newConn(o, nc)
	if err != nil {
		nc.Close()
		return o.recErr(err)
	}
	*connOut = C.int(cfd)
	return o.recErr(nil)
}

//export TailcatClientClose
func TailcatClientClose(cd C.int) C.int {
	o := takeObject(cd, false)
	if o == nil {
		return C.EBADF
	}
	c := o.c
	c.mu.Lock()
	c.closed = true
	cl := c.cl
	c.mu.Unlock()
	closeConnsOf(o)
	if err := cl.Close(); err != nil {
		logf := cl.Logf
		if logf == nil {
			logf = log.Printf
		}
		logf("libtailcat: client close: %v", err)
		return -1
	}
	return 0
}

//export TailcatKeyGenerate
func TailcatKeyGenerate(keyJSONOut **C.char) *C.char {
	if keyJSONOut == nil {
		panic("key_generate passed nil key_json_out")
	}
	*keyJSONOut = nil
	pk := tailcat.NewPrivateKey()
	pk.Public.RegionID = -1 // auto
	b, err := json.MarshalIndent(pk, "", "\t")
	if err != nil {
		return cerr(err)
	}
	*keyJSONOut = C.CString(string(b))
	return nil
}

//export TailcatKeyPublic
func TailcatKeyPublic(keyJSON *C.char, nodekeyOut **C.char) *C.char {
	if nodekeyOut == nil {
		panic("key_public passed nil nodekey_out")
	}
	*nodekeyOut = nil
	pk, err := parsePrivateKey(C.GoString(keyJSON))
	if err != nil {
		return cerr(err)
	}
	*nodekeyOut = C.CString(pk.Private.Public().String())
	return nil
}

//export TailcatKeyToken
func TailcatKeyToken(keyJSON *C.char, tokenOut **C.char) *C.char {
	if tokenOut == nil {
		panic("key_token passed nil token_out")
	}
	*tokenOut = nil
	pk, err := parsePrivateKey(C.GoString(keyJSON))
	if err != nil {
		return cerr(err)
	}
	ci := pk.Public
	switch {
	case ci.RegionID == -1 && len(ci.Region) == 0:
		return cerr(errors.New("the key's DERP region is auto (-1); the token is only known once the server starts"))
	case ci.RegionID == 0 && len(ci.Region) == 0:
		return cerr(errors.New("the key has no DERP region"))
	}
	// The public keys follow from the private key; the server announces
	// exactly these.
	ci.ServerPublic = tailcat.NodePublic{NodePublic: pk.Private.Public()}
	ci.ServerDiscoPublic = tailcat.DiscoPublicForNode(pk.Private)
	*tokenOut = C.CString(string(ci.ConnBlob()))
	return nil
}

//export TailcatTokenParse
func TailcatTokenParse(token *C.char, jsonOut **C.char) *C.char {
	if jsonOut == nil {
		panic("token_parse passed nil json_out")
	}
	*jsonOut = nil
	v, err := tailcat.ParseConnBlobRaw(tailcat.ConnBlob(C.GoString(token)))
	if err != nil {
		return cerr(err)
	}
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return cerr(err)
	}
	*jsonOut = C.CString(string(b))
	return nil
}

//export TailcatTokenResolve
func TailcatTokenResolve(token, derpMapURL *C.char, timeoutMs C.int, tokenOut **C.char) *C.char {
	if tokenOut == nil {
		panic("token_resolve passed nil token_out")
	}
	*tokenOut = nil
	ctx, cancel := timeoutContext(timeoutMs)
	defer cancel()
	var opts []any
	if derpMapURL != nil {
		if u := C.GoString(derpMapURL); u != "" {
			opts = append(opts, tailcat.DERPMapURL(u))
		}
	}
	rb, err := tailcat.ConnBlob(C.GoString(token)).Resolve(ctx, opts...)
	if err != nil {
		return cerr(err)
	}
	*tokenOut = C.CString(string(rb))
	return nil
}
