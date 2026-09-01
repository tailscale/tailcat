// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && !ts_omit_ssh

package tailcat

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	ssh "github.com/tailscale/gliderssh"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// newSessionCommand returns an unstarted command running PowerShell:
// interactively if rawCmd is empty, otherwise running rawCmd with
// PowerShell's -Command flag. The returned command has Args, Dir, and the
// base environment set; the caller appends any client-provided environment.
func newSessionCommand(u *user.User, rawCmd string) *exec.Cmd {
	clearInheritedCtrlCIgnore()
	shell := powerShellPath()

	var args []string
	if rawCmd == "" {
		args = []string{shell, "-NoLogo"}
	} else {
		args = []string{shell, "-Command", rawCmd}
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = u.HomeDir
	// Unlike the minimal environment built on Unix, Windows processes
	// need most of the parent environment (SystemRoot, TEMP, and
	// friends) to function, so the session inherits it wholesale.
	cmd.Env = os.Environ()
	return cmd
}

// powerShellPath returns the path of the Windows PowerShell executable.
func powerShellPath() string {
	// See https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration#configuring-the-default-shell-for-openssh-in-windows
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\OpenSSH`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		shell, _, _ := key.GetStringValue("DefaultShell")
		key.Close()
		name := strings.ToLower(filepath.Base(shell))
		if name == "pwsh.exe" || name == "powershell.exe" {
			if p, err := exec.LookPath(shell); err == nil {
				return p
			}
		}
	}
	if p, err := exec.LookPath("pwsh.exe"); err == nil {
		return p
	}
	pwsh := filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe")
	if p, err := exec.LookPath(pwsh); err == nil {
		return p
	}
	if p, err := exec.LookPath("powershell.exe"); err == nil {
		return p
	}
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procCreatePseudoConsole       = kernel32.NewProc("CreatePseudoConsole")
	procUpdateProcThreadAttribute = kernel32.NewProc("UpdateProcThreadAttribute")
	procSetConsoleCtrlHandler     = kernel32.NewProc("SetConsoleCtrlHandler")
)

// clearInheritedCtrlCIgnore clears this process's "ignore Ctrl-C"
// console flag, which session children inherit at creation. The server
// process can itself inherit the flag from whatever spawned it
// (Win32-OpenSSH's sshd sets it on the shells it starts, for example),
// and a child that inherits it never receives console Ctrl-C events,
// so ^C in an interactive SSH session would be silently dropped.
//
// SetConsoleCtrlHandler(NULL, FALSE) clears the flag without touching
// installed handlers (x/sys/windows has no wrapper for the NULL form).
var clearInheritedCtrlCIgnore = sync.OnceFunc(func() {
	procSetConsoleCtrlHandler.Call(0, 0)
})

// conPTYAvailable reports whether this Windows version has the
// pseudoconsole API (Windows 10 1809 or later). Calling the
// x/sys/windows pseudoconsole functions without this check would
// panic on older systems.
var conPTYAvailable = sync.OnceValue(func() bool {
	return procCreatePseudoConsole.Find() == nil
})

// runWithPTY runs cmd attached to a Windows pseudoconsole (ConPTY). The
// *exec.Cmd is used only as a carrier of Args, Env, and Dir; the process is
// created by startConPTY, never started via the exec package.
func runWithPTY(sess ssh.Session, cmd *exec.Cmd, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	if !conPTYAvailable() {
		fmt.Fprintf(sess.Stderr(), "tailcat: no ConPTY on this Windows version; running without a PTY\r\n")
		runWithPipes(sess, cmd)
		return
	}

	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
	}

	cp, err := startConPTY(cmd, ptyReq.Window.Width, ptyReq.Window.Height)
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "conpty: %v\r\n", err)
		sess.Exit(1)
		return
	}
	defer cp.Close()

	go io.Copy(cp.inWrite, sess) // stdin

	// Handle window size changes. The goroutine runs until gliderssh
	// closes winCh, which happens only once the whole session channel
	// shuts down, possibly after this function has returned; Resize is
	// a no-op once the pseudoconsole has been closed.
	go func() {
		for win := range winCh {
			cp.Resize(win.Width, win.Height)
		}
	}()

	// Drain process output. This reader must be running before the
	// CloseConsole call below: closing the pseudoconsole can block
	// until its pending output has been consumed.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		io.Copy(sess, cp.outRead)
	}()

	code, err := cp.WaitExitCode()

	// Closing the pseudoconsole makes conhost release its handle on
	// the output pipe, which is what lets the reader above see EOF.
	cp.CloseConsole()
	<-outDone

	if err != nil {
		fmt.Fprintf(sess.Stderr(), "wait: %v\r\n", err)
		sess.Exit(1)
		return
	}
	sess.Exit(code)
}

// conPTY is a Windows pseudoconsole with a single process attached to it.
type conPTY struct {
	inWrite *os.File // the attached process reads its input from here
	outRead *os.File // the attached process's output is read from here
	proc    windows.Handle

	mu     sync.Mutex // guards hpc and closed: Resize races CloseConsole
	hpc    windows.Handle
	closed bool
}

// startConPTY creates a pseudoconsole with the given dimensions and starts a
// process attached to it, taking the program arguments, environment, and
// working directory from cmd. The command is never started via the exec
// package: pseudoconsole attachment requires creating the process directly.
func startConPTY(cmd *exec.Cmd, width, height int) (*conPTY, error) {
	// CreatePseudoConsole rejects empty dimensions, which SSH clients
	// without a real terminal (ssh -tt from a pipe, say) can send.
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		return nil, err
	}

	var hpc windows.Handle
	err = windows.CreatePseudoConsole(
		windows.Coord{X: int16(width), Y: int16(height)},
		windows.Handle(inRead.Fd()),
		windows.Handle(outWrite.Fd()),
		0, &hpc)
	// The pseudoconsole duplicates the handles it needs, so our copies
	// of its two pipe ends are closed here regardless of error.
	inRead.Close()
	outWrite.Close()
	if err != nil {
		inWrite.Close()
		outRead.Close()
		return nil, fmt.Errorf("CreatePseudoConsole: %w", err)
	}
	cleanup := func() {
		windows.ClosePseudoConsole(hpc)
		inWrite.Close()
		outRead.Close()
	}

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		cleanup()
		return nil, err
	}
	defer attrs.Delete()
	if err := updatePseudoConsoleAttr(attrs.List(), hpc); err != nil {
		cleanup()
		return nil, err
	}

	cmdLine, err := windows.UTF16FromString(windows.ComposeCommandLine(cmd.Args))
	if err != nil {
		cleanup()
		return nil, err
	}
	var dir *uint16
	if cmd.Dir != "" {
		dir, err = windows.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			cleanup()
			return nil, err
		}
	}
	env, err := envBlock(cmd.Env)
	if err != nil {
		cleanup()
		return nil, err
	}

	si := &windows.StartupInfoEx{
		// STARTF_USESTDHANDLES with the std handles left NULL keeps
		// the child from inheriting this process's console handles;
		// without it the child's output bypasses the pseudoconsole
		// and lands on the parent's console.
		StartupInfo: windows.StartupInfo{
			Cb:    uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags: windows.STARTF_USESTDHANDLES,
		},
		ProcThreadAttributeList: attrs.List(),
	}
	var pi windows.ProcessInformation
	err = windows.CreateProcess(nil, &cmdLine[0], nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		env, dir, &si.StartupInfo, &pi)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}
	windows.CloseHandle(pi.Thread)

	return &conPTY{
		inWrite: inWrite,
		outRead: outRead,
		proc:    pi.Process,
		hpc:     hpc,
	}, nil
}

// updatePseudoConsoleAttr sets the pseudoconsole attribute on the list.
// It calls UpdateProcThreadAttribute directly rather than through the
// x/sys/windows wrapper: the attribute's value is the pseudoconsole handle
// itself rather than a pointer, and converting a handle to the wrapper's
// unsafe.Pointer argument trips go vet's unsafeptr check.
func updatePseudoConsoleAttr(list *windows.ProcThreadAttributeList, hpc windows.Handle) error {
	r1, _, e1 := procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(list)),
		0,
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		uintptr(hpc),
		unsafe.Sizeof(hpc),
		0, 0)
	if r1 == 0 {
		return e1
	}
	return nil
}

// Resize changes the pseudoconsole dimensions. It is a no-op after
// CloseConsole.
func (c *conPTY) Resize(width, height int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	return windows.ResizePseudoConsole(c.hpc, windows.Coord{X: int16(width), Y: int16(height)})
}

// WaitExitCode waits for the attached process to exit and returns its exit
// code.
func (c *conPTY) WaitExitCode() (int, error) {
	if _, err := windows.WaitForSingleObject(c.proc, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(c.proc, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

// CloseConsole closes the pseudoconsole itself, without touching the pipes
// or the process handle.
func (c *conPTY) CloseConsole() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		windows.ClosePseudoConsole(c.hpc)
		c.closed = true
	}
}

// Close releases everything: the pseudoconsole if still open, both pipe
// ends, and the process handle.
func (c *conPTY) Close() {
	c.CloseConsole()
	c.inWrite.Close()
	c.outRead.Close()
	windows.CloseHandle(c.proc)
}

// envBlock converts a []string of key=value pairs to the UTF-16,
// NUL-separated, double-NUL-terminated block CreateProcess expects.
// Windows environment keys are case-insensitive and duplicates are not
// allowed in the block, so later entries (such as client-provided TERM or
// LANG values appended after os.Environ) replace earlier ones.
func envBlock(env []string) (*uint16, error) {
	seen := make(map[string]int) // uppercased key -> index in list
	var list []string
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		uk := strings.ToUpper(k)
		if i, dup := seen[uk]; dup {
			list[i] = kv
		} else {
			seen[uk] = len(list)
			list = append(list, kv)
		}
	}
	var block []uint16
	for _, kv := range list {
		u, err := windows.UTF16FromString(kv) // NUL-terminated
		if err != nil {
			return nil, err
		}
		block = append(block, u...)
	}
	block = append(block, 0)
	return &block[0], nil
}
