// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/peterbourgon/ff/v4"
	"github.com/toqueteos/webbrowser"
)

func browseCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("browse").SetParent(parent)
	return &ff.Command{
		Name:      "browse",
		Usage:     "tailcat browse <tc-addr>",
		ShortHelp: "open a web browser to a tailcat server's port 80",
		LongHelp: `Open a web browser to a tailcat server's port 80.

This is an alias for "tailcat forward --open-browser <tc-addr> 0:80":
it opens http://127.0.0.1:<port>/ in a browser once the local listener
is ready, then blocks, forwarding connections, until interrupted.`,
		Flags: fs,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return usagef("browse takes exactly one <tc-addr>")
			}
			return runForward(ctx, getLogf(), "127.0.0.1", []string{args[0], "0:80"}, openBrowserToListener)
		},
	}
}

// openBrowserToListener opens a web browser to the listener's address
// in the background. If the listener is bound to an unspecified
// address such as 0.0.0.0, the browser opens 127.0.0.1 instead.
func openBrowserToListener(ln net.Listener) {
	addr := ln.Addr().String()
	if ap, err := netip.ParseAddrPort(addr); err == nil && ap.Addr().IsUnspecified() {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(ap.Port())))
	}
	url := "http://" + addr + "/"
	fmt.Fprintf(os.Stderr, "# Opening %s\n", url)
	go func() {
		if err := webbrowser.Open(url); err != nil {
			fmt.Fprintf(os.Stderr, "# opening browser failed: %v\n", err)
		}
	}()
}
