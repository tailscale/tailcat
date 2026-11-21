// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// connLog writes the server-mode access log enabled by
// --log: one line per client admitted or refused and per
// incoming connection, naming the client key the tunnel authenticated
// and the port or service it reached.
//
// It is deliberately separate from --verbose, which turns on the
// library's debug logging. An operator who wants a record of who
// connected shouldn't have to read (or store) all of that.
type connLog struct {
	logf logger.Logf
	srv  *tailcat.Server // set by attach, before any event can arrive

	mu      sync.Mutex
	refused map[key.NodePublic]bool // refused keys already logged
}

// newConnLog returns a connection log writing timestamped lines to
// stderr, keeping them clear of any data written to stdout.
func newConnLog() *connLog {
	return &connLog{logf: log.Printf}
}

// maxLoggedRefusals bounds the set of refused keys connLog remembers
// having logged. A refused client is unauthenticated, so anyone who
// knows the server's address could otherwise grow the set without
// limit by connecting under invented keys. Past the cap, further
// refused keys go unlogged.
const maxLoggedRefusals = 1024

// attach records the server whose events are being logged and wraps
// its [tailcat.Server.AllowClient] hook to log each decision. A nil
// hook allows all clients, as it does unwrapped. It must be called
// after AllowClient is set and before [tailcat.Server.Start].
func (l *connLog) attach(s *tailcat.Server) {
	l.srv = s
	next := s.AllowClient
	s.AllowClient = func(k key.NodePublic) bool {
		if next == nil || next(k) {
			l.logf("[peer] allowed key=%v", k)
			return true
		}
		// A refused client retries about once a second until it
		// gives up, and the hook is asked each time, so log each
		// refused key only once.
		if l.firstRefusal(k) {
			l.logf("[peer] refused key=%v reason=not-in-allow", k)
		}
		return false
	}
}

// firstRefusal records that k was refused, reporting whether this is
// the first refusal of k to be logged.
func (l *connLog) firstRefusal(k key.NodePublic) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refused[k] || len(l.refused) >= maxLoggedRefusals {
		return false
	}
	if l.refused == nil {
		l.refused = make(map[key.NodePublic]bool)
	}
	l.refused[k] = true
	return true
}

// wrapTCP returns a handler that logs the connection to dst, given as
// key=value pairs, around running next.
//
// A nil next means the server is about to refuse the connection; that
// is logged and nil returned, so the server still answers with a RST.
// The refusal is reported without a peer key because the server
// decides it from the port alone, before any connection exists to
// trace back to a peer.
//
// The returned handler passes the connection to next unwrapped: a
// wrapped net.Conn would hide the *gonet.TCPConn that
// [tailcat.ProxyConns] needs to shut a tunnel connection down without
// losing its FIN.
func (l *connLog) wrapTCP(dst string, next func(net.Conn)) func(net.Conn) {
	if next == nil {
		l.logf("[conn] refused %v", dst)
		return nil
	}
	return func(c net.Conn) {
		peer := "unknown"
		via := "unknown"
		if k, ok := l.srv.PeerKey(c.RemoteAddr()); ok {
			peer = k.String()
			via = l.path(k)
		}
		l.logf("[conn] open peer=%v %v via=%v", peer, dst, via)
		start := time.Now()
		defer func() {
			l.logf("[conn] close peer=%v %v duration=%v", peer, dst, time.Since(start).Round(time.Millisecond))
		}()
		next(c)
	}
}

// path reports how packets currently reach peer k: the direct UDP
// endpoint if one has been negotiated, else the DERP region relaying
// for it. This is the only place a client's real network address
// appears, and only once a direct path exists; a client's tailcat
// address is derived from its key and so says nothing the key doesn't.
func (l *connLog) path(k key.NodePublic) string {
	ps, ok := l.srv.Status().Peer[k]
	if !ok {
		return "unknown"
	}
	switch {
	case ps.CurAddr != "":
		return "direct:" + ps.CurAddr
	case ps.Relay != "":
		return "derp:" + ps.Relay
	}
	return "unknown"
}
