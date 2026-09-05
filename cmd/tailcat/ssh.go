// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const tailCatSSHEnabled = true

const sshLongHelp = `Examples:

	tailcat ssh <tc-addr>
	tailcat ssh root@<tc-addr>
	tailcat ssh <tc-addr> uptime
	tailcat ssh example.com
	tailcat ssh -p 2222 <tc-addr>
	tailcat ssh -p 10.0.0.1:22 <tc-addr>

This execs the system ssh client with a ProxyCommand that runs
tailcat itself, so ssh sees a normal (if oddly named) destination
while the connection actually goes over tailcat to the server.
Anything after the destination is passed through to ssh, like a
remote command to run.
A DNS name whose "tailcat=" TXT record holds a tailcat address works
as the destination too.

A DNS TXT record is public, so a DNS-named destination is first
probed the way a stranger would connect: with a freshly generated
client key and no SSH credentials. If the server lets that stranger
log in, tailcat refuses to connect, because anyone on the internet
who reads the TXT record could do the same. The
--skip-dns-safety-check flag skips the probe, either to connect
anyway or to save the probe's round trips.

The -p flag is the server port to connect to (default 22), or, if
the server is an exit node (--serve=exit-node), an ip:port on the
server's network to reach through it; a bare IP means its port 22.`

// sshCommand returns the "tailcat ssh" subcommand, with parent as the
// parent flag set for the global flags.
func sshCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("ssh").SetParent(parent)
	port := fs.StringShort('p', "22", "port number, or ip:port to reach via the server's exit node; a bare IP means port 22 on it")
	skipDNSCheck := fs.BoolLong("skip-dns-safety-check", "don't probe a DNS-named destination for whether its server gives SSH access to strangers (anyone who reads its public TXT record); skipping also saves the probe's round trips")
	return &ff.Command{
		Name:      "ssh",
		Usage:     "tailcat ssh [-p <port|ip:port>] [user@]<tc-addr> [<command> [args...]]",
		ShortHelp: "connect the system ssh client through a tailcat server",
		LongHelp:  sshLongHelp,
		Flags:     fs,
		Exec: func(ctx context.Context, args []string) error {
			return clientSSHMode(*port, *skipDNSCheck, args)
		},
	}
}

func clientSSHMode(portOrIPPort string, skipDNSCheck bool, args []string) error {
	if len(args) == 0 {
		return usagef("ssh requires a [user@]<tc-addr> destination argument")
	}
	portOrIPPort, err := validatedSSHPort(portOrIPPort)
	if err != nil {
		return err
	}
	dst := args[0] // either a tailcat address alone or "user@<tc-addr>"
	cmdArgs := args[1:]

	sshUser, addrStr, hasUser := strings.Cut(dst, "@")
	if !hasUser {
		addrStr = sshUser
		sshUser = ""
	}
	dnsName := addrStr
	addrStr, viaDNS, err := validatedAddr(addrStr)
	if err != nil {
		return err
	}
	if viaDNS && !skipDNSCheck {
		refuseWideOpenDNS(dnsName, addrStr, portOrIPPort, sshUser)
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	sshExe, err := exec.LookPath("ssh")
	if err != nil {
		log.Fatalf("no ssh client found in $PATH: %v", err)
	}
	sshDst := sshDestHost(addrStr)
	if sshUser != "" {
		sshDst = sshUser + "@" + sshDst
	}
	proxyCommand, err := sshProxyCommand(exe, *flagKey, *flagDERPMapURL, addrStr, portOrIPPort)
	if err != nil {
		return err
	}
	argv := []string{
		sshExe,
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile " + os.DevNull,
		"-o", "LogLevel ERROR",
		"-o", "ProxyCommand=" + proxyCommand,
		"--",
		sshDst,
	}
	argv = append(argv, cmdArgs...)
	err = execSSH(sshExe, argv)
	log.Fatalf("failed to run ssh: %v", err)
	return nil
}

// validatedSSHPort validates and canonicalizes the port or IP:port passed to
// tailcat's child ProxyCommand. A bare IP means port 22.
func validatedSSHPort(v string) (string, error) {
	if port, err := strconv.ParseUint(v, 10, 16); err == nil && port != 0 {
		return strconv.FormatUint(port, 10), nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return netip.AddrPortFrom(ip, 22).String(), nil
	}
	if ipPort, err := netip.ParseAddrPort(v); err == nil && ipPort.Port() != 0 {
		return ipPort.String(), nil
	}
	return "", usagef("invalid port or IP:port %q", v)
}

// validatedAddr resolves arg if it is a DNS name and verifies that the
// result is a valid tailcat address before it is handed to ssh or scp.
// viaDNS reports whether the address came from a public DNS TXT record
// rather than being supplied directly.
func validatedAddr(arg string) (addr string, viaDNS bool, err error) {
	a := tailcat.Addr(arg)
	if strings.Contains(arg, ".") {
		a = tailcatAddrArg(arg)
		viaDNS = true
	}
	if _, err := tailcat.ParseAddr(a); err != nil {
		return "", false, fmt.Errorf("invalid tailcat address %q: %w", arg, err)
	}
	return string(a), viaDNS, nil
}

// refuseWideOpenDNS probes the server whose tailcat address addr came
// from the public DNS TXT record of dnsName, and exits the process
// with a warning if the server gives SSH access to strangers. Probe
// failures are not fatal: a server protected by --allow ignores
// strangers entirely, so the probe times out, and any other failure
// recurs in the real connection that follows, with a better error.
func refuseWideOpenDNS(dnsName, addr, portOrIPPort, sshUser string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open, err := probeStrangerSSH(ctx, getLogf(), *flagDERPMapURL, addr, portOrIPPort, sshUser)
	if err != nil {
		if *flagVerbose {
			log.Printf("stranger probe of %s did not connect: %v", dnsName, err)
		}
		return
	}
	if !open {
		return
	}
	log.Fatalf(`⚠️ WARNING: refusing to connect to %s: its SSH server is wide open.

The tailcat address in its DNS TXT record is public, and the server
accepted an SSH login from a freshly generated client key offering
no SSH credentials at all. Anyone on the internet who reads that DNS
record can get a shell.

If that's your server, stop running it now, and restart it only once
it requires client authentication:

  tailcat serve --allow=<client-nodekey> ...        (tunnel layer)
  tailcat serve --ssh-authorized-keys=<keys> ssh    (SSH layer)

Or, to connect anyway, re-run with --skip-dns-safety-check.`, dnsName)
}

// probeStrangerSSH reports whether the tailcat server at addr grants
// SSH access to a stranger. It connects with a freshly generated node
// key and attempts an SSH handshake as sshUser (the local username if
// empty, matching the ssh client's default) offering no credentials,
// only the "none" auth method, which the no-auth-ssh service accepts
// before public key auth would even come up. It makes no command or
// PTY request and disconnects. Open false with a nil error means the
// server rejected the stranger's handshake.
func probeStrangerSSH(ctx context.Context, logf logger.Logf, derpMapURL, addr, portOrIPPort, sshUser string) (open bool, err error) {
	cl := &tailcat.Client{
		Server:       tailcat.Addr(addr),
		Key:          key.NewNode(),
		Logf:         logf,
		DERPMapURL:   derpMapURL,
		DERPMapCache: derpMapCache{},
	}
	var conn net.Conn
	if ipPort, err2 := netip.ParseAddrPort(portOrIPPort); err2 == nil {
		conn, err = cl.DialTCP(ctx, ipPort)
	} else {
		port, err2 := strconv.ParseUint(portOrIPPort, 10, 16)
		if err2 != nil {
			return false, fmt.Errorf("invalid port %q", portOrIPPort)
		}
		conn, err = cl.DialTCPPort(ctx, uint16(port))
	}
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if sshUser == "" {
		u, err := user.Current()
		if err != nil {
			return false, err
		}
		sshUser = u.Username
	}
	sc, chans, reqs, err := gossh.NewClientConn(conn, addr, &gossh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return false, nil
	}
	gossh.NewClient(sc, chans, reqs).Close()
	return true, nil
}

// sshProxyCommand returns the command passed to OpenSSH to connect the SSH
// client to a tailcat server. The command is run by OpenSSH, so values that
// can contain shell-special characters must be quoted.
func sshProxyCommand(exe, keyName, derpMapURL, addr, portOrIPPort string) (string, error) {
	args := []string{exe}
	// No --key flag at all when unset: ff parses --key= by consuming the
	// tailcat address as the flag's value.
	if keyName != "" {
		args = append(args, "--key="+keyName)
	}
	if derpMapURL != tailcat.DefaultDERPMapURL {
		args = append(args, "--derpmap-url="+derpMapURL)
	}
	args = append(args, addr, portOrIPPort)
	if runtime.GOOS == "windows" {
		return proxyCommandJoinWindows(args)
	}
	return proxyCommandJoinUnix(args)
}

// proxyCommandJoinUnix quotes args for the POSIX shell OpenSSH uses to run a
// ProxyCommand. Percent signs are doubled for OpenSSH's own token expansion;
// it changes %% back to % before handing the command to the shell.
func proxyCommandJoinUnix(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return "", fmt.Errorf("ProxyCommand argument contains a control character: %q", arg)
		}
		arg = strings.ReplaceAll(arg, "%", "%%")
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
	}
	return strings.Join(quoted, " "), nil
}

// proxyCommandJoinWindows quotes args for cmd.exe, which Win32-OpenSSH uses
// to run a ProxyCommand. cmd.exe expands %variables% and, depending on
// configuration, !variables! even inside quotes, so reject those characters
// rather than claiming they can be safely escaped through both OpenSSH and
// cmd.exe.
func proxyCommandJoinWindows(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, "\"%!\r\n\x00") {
			return "", fmt.Errorf("ProxyCommand argument contains a character unsafe for cmd.exe: %q", arg)
		}
		quoted[i] = quoteWindowsCommandArg(arg)
	}
	return strings.Join(quoted, " "), nil
}

// quoteWindowsCommandArg always double-quotes arg, protecting cmd.exe
// metacharacters, and doubles trailing backslashes as required by the Windows
// argv parser used by the tailcat child. Embedded quotes are rejected above
// because cmd.exe and that argv parser assign them incompatible meanings.
func quoteWindowsCommandArg(arg string) string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(arg)
	b.WriteString(strings.Repeat("\\", len(arg)-len(strings.TrimRight(arg, "\\"))))
	b.WriteByte('"')
	return b.String()
}

// sshDestHost returns the hostname to give the system ssh client as the
// connection destination for a tailcat Addr. It is a short, deterministic
// function of the address rather than the address itself.
//
// ssh substitutes the literal destination hostname into %n in ControlPath
// (commonly "~/.ssh/master-%r@%n:%p"), and that expansion has to fit in an
// AF_UNIX socket path (~100 bytes total, including the home directory and
// ".ssh/master-" prefix). An Addr can run past that on its own, so ssh
// with connection multiplexing fails with "too long for Unix domain socket"
// before tailcat is ever invoked (#12). The real address is unaffected: it's
// passed to ProxyCommand as its own argument and still does the actual
// routing, so this string only ever labels the connection for ssh's
// bookkeeping (%n, and StrictHostKeyChecking is already off).
//
// Deterministic hashing, not address truncation, matters here: ssh's connection
// sharing keys a control socket off ControlPath, so the same address must
// always produce the same short host or multiplexing silently stops
// reusing (or worse, collides across) the right server.
func sshDestHost(addr string) string {
	sum := sha256.Sum256([]byte(addr))
	return "tailcat-" + hex.EncodeToString(sum[:8])
}
