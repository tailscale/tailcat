// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

// TestDERPWebsocketFallback checks that a Server and Client get through a
// DERP server that, like some HTTP proxies, refuses the usual "Upgrade: DERP"
// request and only allows WebSocket upgrades.
func TestDERPWebsocketFallback(t *testing.T) {
	t.Parallel()

	logf := mkLogger(t, "derp")
	d := derpserver.New(key.NewNode(), logf)
	t.Cleanup(func() { d.Close() })
	noDERPUpgrade := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "derp") {
			http.Error(w, "DERP upgrade blocked", http.StatusForbidden)
			return
		}
		derpserver.Handler(d).ServeHTTP(w, r)
	})
	httpsrv := httptest.NewUnstartedServer(derpserver.AddWebSocketSupport(d, noDERPUpgrade))
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	t.Cleanup(httpsrv.Close)

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(stunCleanup)

	reg := &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name:             "t1",
			RegionID:         1,
			HostName:         "127.0.0.1",
			IPv4:             "127.0.0.1",
			IPv6:             "none",
			STUNPort:         stunAddr.Port,
			DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
			InsecureForTests: true,
			STUNTestIP:       "127.0.0.1",
		}},
	}

	s := &Server{Key: key.NewNode(), Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		return func(c net.Conn) {
			io.WriteString(c, "Hello over WebSockets\n")
			c.Close()
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	c := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if want := "Hello over WebSockets\n"; string(got) != want {
		t.Errorf("got %q; want %q", got, want)
	}
}
