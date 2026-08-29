// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/logger"
)

const tailCatSSHEnabled = true

func clientSSHMode(logf logger.Logf) {
	args := flag.Args()
	args = args[1:] // trim off "ssh"
	if len(args) == 0 {
		usage("tailcat ssh [-p <port|ip:port>] [user@]<addrblob> [command ...]")
	}

	portOrIPPort := "22"
	if len(args) >= 2 && args[0] == "-p" {
		portOrIPPort = args[1]
		args = args[2:]
		if ip, err := netip.ParseAddr(portOrIPPort); err == nil {
			portOrIPPort = netip.AddrPortFrom(ip, 22).String()
		}
	}
	dst := args[0] // either a derpaddr alone or "user@<derpaddr>"
	cmdArgs := args[1:]

	sshUser, connBlobStr, hasUser := strings.Cut(dst, "@")
	if !hasUser {
		connBlobStr = sshUser
		sshUser = ""
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	sshExe, err := exec.LookPath("ssh")
	if err != nil {
		log.Fatalf("no ssh client found in $PATH: %v", err)
	}
	sshDst := sshDestHost(connBlobStr)
	if sshUser != "" {
		sshDst = sshUser + "@" + sshDst
	}
	argv := []string{
		sshExe,
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile /dev/null",
		"-o", "LogLevel ERROR",
		"-o", "ProxyCommand=" + sshProxyCommand(exe, *flagKey, *flagDERPMapURL, connBlobStr, portOrIPPort),
		sshDst,
	}
	argv = append(argv, cmdArgs...)
	err = syscall.Exec(sshExe, argv, os.Environ())
	log.Fatalf("failed to exec: %v", err)
}

// sshProxyCommand returns the command passed to OpenSSH to connect the SSH
// client to a tailcat server. The command is run by OpenSSH, so values that
// can contain shell-special characters must be quoted.
func sshProxyCommand(exe, keyName, derpMapURL, connBlob, portOrIPPort string) string {
	cmd := fmt.Sprintf("%s --key=%q", exe, keyName)
	if derpMapURL != tailcat.DefaultDERPMapURL {
		cmd += fmt.Sprintf(" --derpmap-url=%q", derpMapURL)
	}
	return fmt.Sprintf("%s %s %s", cmd, connBlob, portOrIPPort)
}

// sshDestHost returns the hostname to give the system ssh client as the
// connection destination for a tailcat ConnBlob. It is a short, deterministic
// function of blob rather than blob itself.
//
// ssh substitutes the literal destination hostname into %n in ControlPath
// (commonly "~/.ssh/master-%r@%n:%p"), and that expansion has to fit in an
// AF_UNIX socket path (~100 bytes total, including the home directory and
// ".ssh/master-" prefix). A ConnBlob can run past that on its own, so ssh
// with connection multiplexing fails with "too long for Unix domain socket"
// before tailcat is ever invoked (#12). The real blob is unaffected: it's
// passed to ProxyCommand as its own argument and still does the actual
// routing, so this string only ever labels the connection for ssh's
// bookkeeping (%n, and StrictHostKeyChecking is already off).
//
// Deterministic hashing, not blob truncation, matters here: ssh's connection
// sharing keys a control socket off ControlPath, so the same blob must
// always produce the same short host or multiplexing silently stops
// reusing (or worse, collides across) the right server.
func sshDestHost(blob string) string {
	sum := sha256.Sum256([]byte(blob))
	return "tailcat-" + hex.EncodeToString(sum[:8])
}
