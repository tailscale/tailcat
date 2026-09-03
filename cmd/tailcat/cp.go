// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/peterbourgon/ff/v4"
)

// cpCommand returns the "tailcat cp" subcommand, with parent as the
// parent flag set for the global flags.
func cpCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("cp").SetParent(parent)
	recursive := fs.BoolShort('r', "recursively copy directories")
	preserve := fs.BoolShort('p', "preserve modification times and modes")
	port := fs.StringShort('P', "22", "port number of the server's SSH (file service) port")
	return &ff.Command{
		Name:      "cp",
		Usage:     "tailcat cp [-r] [-p] <source>... <target>",
		ShortHelp: "copy files to or from a tailcat server, using the system scp",
		LongHelp:  cpLongHelp,
		Flags:     fs,
		Exec: func(ctx context.Context, args []string) error {
			return clientCPMode(*recursive, *preserve, *port, args)
		},
	}
}

const cpLongHelp = `Remote paths are written <tc-addr>:[path], like scp's host:path.
Paths are relative to the server's served directory ("tailcat serve
files"), or to the remote home directory for a full SSH server
("tailcat serve no-auth-ssh"). A DNS name with a "tailcat=" TXT
record works in place of a tailcat address.

Copy a file to a server, keeping its name, and fetch it back:

	tailcat cp foo.txt <tc-addr>:
	tailcat cp <tc-addr>:foo.txt copy.txt

Copy a directory tree to a directory the server offers read-write:

	tailcat cp -r ./photos <tc-addr>:photos

The actual copying is done by the system scp, with the connection
routed through tailcat, so scp's progress display applies.`

// clientCPMode runs the system scp with all remote arguments routed
// through one tailcat server.
func clientCPMode(recursive, preserve bool, portOrIPPort string, args []string) error {
	if len(args) < 2 {
		return usagef("cp requires at least one source and a target")
	}
	portOrIPPort, err := validatedSSHPort(portOrIPPort)
	if err != nil {
		return err
	}

	// Find the server named by the remote arguments before translating
	// them to scp host:path arguments.
	addr := ""
	for _, arg := range args {
		host, _, ok := splitRemoteArg(arg)
		if !ok {
			continue
		}
		if addr != "" && host != addr {
			return usagef("all remote paths must name the same server (%q and %q differ)", addr, host)
		}
		addr = host
	}
	if addr == "" {
		return usagef("no remote <tc-addr>:path argument; nothing to copy through tailcat")
	}
	addr, err = validatedAddr(addr)
	if err != nil {
		return err
	}

	// Give scp a short deterministic host label; the validated address does
	// the actual routing inside ProxyCommand.
	scpArgs := make([]string, 0, len(args))
	for _, arg := range args {
		_, path, ok := splitRemoteArg(arg)
		if !ok {
			scpArgs = append(scpArgs, arg)
			continue
		}
		scpArgs = append(scpArgs, sshDestHost(addr)+":"+path)
	}

	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	scpExe, err := exec.LookPath("scp")
	if err != nil {
		log.Fatalf("no scp found in $PATH: %v", err)
	}
	proxyCommand, err := sshProxyCommand(exe, proxyFlags(), addr, portOrIPPort)
	if err != nil {
		return err
	}
	argv := []string{
		scpExe,
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile " + os.DevNull,
		"-o", "LogLevel ERROR",
		"-o", "ProxyCommand=" + proxyCommand,
	}
	if recursive {
		argv = append(argv, "-r")
	}
	if preserve {
		argv = append(argv, "-p")
	}
	argv = append(argv, "--")
	argv = append(argv, scpArgs...)
	err = execSSH(scpExe, argv)
	log.Fatalf("failed to run scp: %v", err)
	return nil
}

// splitRemoteArg splits an scp-style remote argument "host:path",
// where host is a tailcat address or a DNS name with a "tailcat=" TXT
// record. ok reports whether arg is remote: it has a colon that
// isn't preceded by a path separator, and the part before the colon
// is longer than one character (so a Windows drive path like
// "C:\foo" stays local).
func splitRemoteArg(arg string) (host, path string, ok bool) {
	i := strings.Index(arg, ":")
	if i <= 1 {
		return "", "", false
	}
	if strings.ContainsAny(arg[:i], `/\`) {
		return "", "", false
	}
	return arg[:i], arg[i+1:], true
}
