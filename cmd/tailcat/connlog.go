// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"log"
	"net"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// connLog writes the server-mode access log enabled by
// --log-connections: one line per peer handshake and per incoming
// connection, naming the client key the tunnel authenticated and the
// port or service it reached.
//
// It is deliberately separate from --verbose, which turns on the
// library's debug logging. An operator who wants a record of who
// connected shouldn't have to read (or store) all of that.
type connLog struct {
	logf logger.Logf
	srv  *tailcat.Server // set by attach, before any event can arrive
}

// newConnLog returns a connection log writing timestamped lines to
// stderr, keeping them clear of any data written to stdout.
func newConnLog() *connLog {
	return &connLog{logf: log.Printf}
}

// attach records the server whose events are being logged and installs
// the peer callback. It must be called before [tailcat.Server.Start].
func (l *connLog) attach(s *tailcat.Server) {
	l.srv = s
	s.OnPeer = l.onPeer
}

// onPeer is the [tailcat.Server.OnPeer] callback, reporting each
// client key the first time it completes the tunnel handshake.
func (l *connLog) onPeer(k key.NodePublic, allowed bool) {
	if allowed {
		l.logf("[peer] allowed key=%v", k)
	} else {
		l.logf("[peer] refused key=%v reason=not-in-allow", k)
	}
}

// wrapTCP returns a handler that logs the connection to dst, given as
// key=value pairs, around running next.
//
// A nil next means the server is about to refuse the connection; that
// is logged and nil returned, so the server still answers with a RST.
// The refusal is reported without a peer key because the server
// decides it from the port alone, before any connection exists to
// trace back to a peer.
func (l *connLog) wrapTCP(dst string, next func(net.Conn)) func(net.Conn) {
	if next == nil {
		l.logf("[conn] refused %v", dst)
		return nil
	}
	return func(c net.Conn) {
		peer := "unknown"
		via := "unknown"
		if k, ok := l.srv.PeerKeyForConn(c); ok {
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
