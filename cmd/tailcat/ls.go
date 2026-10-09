// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/types/logger"
)

// lsCommand returns the "tailcat ls" subcommand, with parent as the
// parent flag set for the global flags.
func lsCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("ls").SetParent(parent)
	long := fs.BoolShort('l', "long listing: permissions, size, and modification time")
	return &ff.Command{
		Name:      "ls",
		Usage:     "tailcat ls [-l] <tc-addr>[:path]",
		ShortHelp: "list files on a tailcat server",
		LongHelp:  lsLongHelp,
		Flags:     fs,
		Exec: func(ctx context.Context, args []string) error {
			return clientLSMode(getLogf(), *long, args)
		},
	}
}

const lsLongHelp = `List the files a tailcat server offers ("tailcat serve files" or a
ssh or no-auth-ssh server), speaking SFTP directly: no ssh or sftp binary
is involved.

List the served directory, or a path under it:

	tailcat ls <tc-addr>
	tailcat ls -l <tc-addr>:photos

A DNS name with a "tailcat=" TXT record works in place of an address
addr.`

// clientLSMode lists path (default the served root) on the server.
func clientLSMode(logf logger.Logf, long bool, args []string) error {
	if len(args) != 1 {
		return usagef("ls requires one <tc-addr>[:path] argument")
	}
	host, path, ok := splitRemoteArg(args[0])
	if !ok {
		host = args[0]
	}
	if path == "" {
		path = "."
	}

	cl := newClient(logf, tailcatAddrArg(host), clientKey())
	defer cl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := cl.DialTCPPort(ctx, 22)
	if err != nil {
		return fmt.Errorf("dialing server: %w", err)
	}
	// The WireGuard tunnel already authenticated the server by its
	// node key in the tailcat address, so the SSH host key adds nothing.
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, "tailcat", &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake: %w", err)
	}
	sc := gossh.NewClient(sshConn, chans, reqs)
	defer sc.Close()
	sf, err := sftp.NewClient(sc)
	if err != nil {
		return fmt.Errorf("opening SFTP session: %w", err)
	}
	defer sf.Close()

	fi, err := sf.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !fi.IsDir() {
		printEntry(long, fi, strings.TrimPrefix(path, "./"))
		return nil
	}
	fis, err := sf.ReadDir(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	slices.SortFunc(fis, func(a, b fs.FileInfo) int {
		return strings.Compare(a.Name(), b.Name())
	})
	for _, fi := range fis {
		printEntry(long, fi, fi.Name())
	}
	return nil
}

// printEntry prints one ls output line for fi. Directories get a
// trailing slash. Long mode adds permissions, size, and modification
// time.
func printEntry(long bool, fi fs.FileInfo, name string) {
	if fi.IsDir() {
		name += "/"
	}
	if !long {
		fmt.Println(name)
		return
	}
	mtime := fi.ModTime()
	format := "Jan _2 15:04"
	if time.Since(mtime) > 180*24*time.Hour {
		format = "Jan _2  2006"
	}
	fmt.Printf("%s %12d %s %s\n", fi.Mode(), fi.Size(), mtime.Format(format), name)
}
