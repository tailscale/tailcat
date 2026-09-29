// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command capitest provides a local DERP/STUN relay and HTTP services for foreign
// language integration tests. It prints one JSON record and runs until stdin EOF.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	cert := flag.String("cert", "", "TLS certificate")
	certKey := flag.String("key", "", "TLS private key")
	flag.Parse()
	envknob.Setenv("IN_TS_TEST", "true")
	d := derpserver.New(key.NewNode(), logger.Discard)
	defer d.Close()
	relay := httptest.NewUnstartedServer(derpserver.Handler(d))
	relay.Config.ErrorLog = logger.StdLogger(logger.Discard)
	relay.StartTLS()
	defer relay.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	check(err)
	defer udp.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err == nil {
				udp.WriteToUDPAddrPort(stun.Response(tx, addr), addr)
			}
		}
	}()
	region := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{
		Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: relay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: udp.LocalAddr().(*net.UDPAddr).Port,
		InsecureForTests: true, STUNTestIP: "127.0.0.1",
	}}}
	s := &tailcat.Server{Region: region, Logf: logger.Discard}
	defer s.Close()
	ln, err := s.Listen(context.Background(), "tcp", ":0")
	check(err)
	tlsLn, err := s.Listen(context.Background(), "tcp", ":0")
	check(err)
	type connKey struct{}
	var connID atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Connection-ID", fmt.Sprint(r.Context().Value(connKey{})))
		switch r.URL.Path {
		case "/slow":
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
				return
			}
		case "/redirect":
			http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
			return
		case "/stream":
			w.Header().Set("Content-Type", "application/octet-stream")
			for i := range 8 {
				fmt.Fprintf(w, "chunk-%d\n", i)
				w.(http.Flusher).Flush()
				select {
				case <-time.After(20 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
			return
		case "/close":
			w.Header().Set("Connection", "close")
		case "/idle-close":
			// Deliberately close without a Connection header to exercise idle EOF probing.
			h, ok := w.(http.Hijacker)
			if !ok {
				panic("no hijacker")
			}
			conn, rw, err := h.Hijack()
			if err != nil {
				return
			}
			fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			rw.Flush()
			conn.Close()
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		w.Header().Add("X-Repeated", "one")
		w.Header().Add("X-Repeated", "two")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "path": r.URL.RequestURI(), "host": r.Host, "body": string(body), "headers": r.Header})
	})
	makeHTTP := func() *http.Server {
		return &http.Server{Handler: handler, ErrorLog: logger.StdLogger(logger.Discard), ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, connID.Add(1))
		}}
	}
	httpServer, httpsServer := makeHTTP(), makeHTTP()
	defer httpServer.Close()
	defer httpsServer.Close()
	go httpServer.Serve(ln)
	pair, err := tls.LoadX509KeyPair(*cert, *certKey)
	check(err)
	go httpsServer.Serve(tls.NewListener(tlsLn, &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}))
	port := func(ln net.Listener) int {
		_, p, _ := net.SplitHostPort(ln.Addr().String())
		n, _ := strconv.Atoi(p)
		return n
	}
	check(json.NewEncoder(os.Stdout).Encode(map[string]any{"address": s.TailcatAddr(), "region": region, "http_port": port(ln), "https_port": port(tlsLn)}))
	io.Copy(io.Discard, os.Stdin)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
