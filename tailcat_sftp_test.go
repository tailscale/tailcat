// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package tailcat_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"

	"github.com/pkg/sftp"
	"github.com/tailscale/tailcat"
)

// newServeDir returns a directory with some existing content to serve:
// existing.txt, sub/, sub/inner.txt, and (except on Windows) an
// escape symlink pointing at a secret file outside the directory.
func newServeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("existing content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "inner.txt"), []byte("inner"), 0644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		outside := filepath.Join(t.TempDir(), "secret.txt")
		if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// sftpClient connects an SFTP client to a rooted file service for dir
// with the given mode, over an in-memory pipe with no SSH transport.
func sftpClient(t *testing.T, dir string, mode tailcat.FileServeMode) *sftp.Client {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	go tailcat.ServeRootedSFTPForTest(srvConn, &tailcat.FileService{Dir: dir, Mode: mode})
	c, err := sftp.NewClientPipe(cliConn, cliConn)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readFile(c *sftp.Client, name string) (string, error) {
	f, err := c.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	all, err := io.ReadAll(f)
	return string(all), err
}

func writeFile(c *sftp.Client, name, content string) error {
	// O_WRONLY, not sftp.Client.Create's O_RDWR: upload tools like
	// scp open write-only, and write-only mode rejects readable
	// handles.
	f, err := c.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(content)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func TestSFTPReadOnly(t *testing.T) {
	c := sftpClient(t, newServeDir(t), tailcat.FileServeRO)

	if got, err := readFile(c, "existing.txt"); err != nil || got != "existing content" {
		t.Errorf("read existing.txt = %q, %v; want %q, nil", got, err, "existing content")
	}
	fis, err := c.ReadDir("/")
	if err != nil {
		t.Errorf("ReadDir: %v", err)
	} else if len(fis) < 2 {
		t.Errorf("ReadDir returned %d entries; want at least existing.txt and sub", len(fis))
	}
	if got, err := readFile(c, "sub/inner.txt"); err != nil || got != "inner" {
		t.Errorf("read sub/inner.txt = %q, %v; want %q, nil", got, err, "inner")
	}
	if _, err := c.Stat("existing.txt"); err != nil {
		t.Errorf("Stat existing.txt: %v", err)
	}

	if err := writeFile(c, "new.txt", "x"); err == nil {
		t.Error("Create succeeded in read-only mode")
	}
	if err := c.Remove("existing.txt"); err == nil {
		t.Error("Remove succeeded in read-only mode")
	}
	if err := c.Mkdir("newdir"); err == nil {
		t.Error("Mkdir succeeded in read-only mode")
	}
	if err := c.Rename("existing.txt", "renamed.txt"); err == nil {
		t.Error("Rename succeeded in read-only mode")
	}
	if err := c.Chmod("existing.txt", 0600); err == nil {
		t.Error("Chmod succeeded in read-only mode")
	}
}

func TestSFTPReadWrite(t *testing.T) {
	c := sftpClient(t, newServeDir(t), tailcat.FileServeRW)

	if err := writeFile(c, "new.txt", "hello"); err != nil {
		t.Fatalf("Create new.txt: %v", err)
	}
	if got, err := readFile(c, "new.txt"); err != nil || got != "hello" {
		t.Errorf("read back new.txt = %q, %v; want %q, nil", got, err, "hello")
	}
	if err := c.Mkdir("newdir"); err != nil {
		t.Errorf("Mkdir: %v", err)
	}
	if err := c.Rename("new.txt", "newdir/moved.txt"); err != nil {
		t.Errorf("Rename: %v", err)
	}
	if err := c.Chmod("newdir/moved.txt", 0600); err != nil {
		t.Errorf("Chmod: %v", err)
	}
	if err := c.Remove("newdir/moved.txt"); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if err := c.RemoveDirectory("newdir"); err != nil {
		t.Errorf("RemoveDirectory: %v", err)
	}
}

// TestSFTPNoSymlinkEscape verifies that a symlink inside the served
// directory pointing outside of it can't be read through: os.Root
// refuses to follow it.
func TestSFTPNoSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no symlinks in the test fixture on Windows")
	}
	c := sftpClient(t, newServeDir(t), tailcat.FileServeRW)
	if got, err := readFile(c, "escape"); err == nil {
		t.Errorf("read through escape symlink succeeded, got %q; want error", got)
	}
}

func TestSFTPWriteOnly(t *testing.T) {
	dir := newServeDir(t)
	c := sftpClient(t, dir, tailcat.FileServeWO)
	originalInfo, err := os.Stat(filepath.Join(dir, "existing.txt"))
	if err != nil {
		t.Fatal(err)
	}

	// A flat drop box always accepts the same client-visible name and stores
	// each upload under a different server-chosen root-level name. Whether the
	// requested name exists is therefore not observable through the result.
	for i, content := range []string{"first", "second"} {
		if err := writeFile(c, "existing.txt", content); err != nil {
			t.Fatalf("upload %d of existing.txt: %v", i+1, err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(dir, "existing.txt")); err != nil {
		t.Fatalf("ReadFile existing.txt: %v", err)
	} else if string(got) != "existing content" {
		t.Errorf("original existing.txt after uploads = %q; want %q", got, "existing content")
	}
	wantName := regexp.MustCompile(`^existing\.[0-9]{14}\.[0-9a-f]{16}\.txt$`)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var uploaded, contents []string
	for _, entry := range entries {
		if !wantName.MatchString(entry.Name()) {
			continue
		}
		uploaded = append(uploaded, entry.Name())
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents = append(contents, string(b))
	}
	if len(uploaded) != 2 {
		t.Fatalf("timestamped existing.txt uploads = %q; want two", uploaded)
	}
	sort.Strings(contents)
	if contents[0] != "first" || contents[1] != "second" {
		t.Errorf("uploaded contents = %q; want first and second", contents)
	}
	if err := c.Chmod("existing.txt", 0600); err != nil {
		t.Errorf("Chmod client-visible existing.txt: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "existing.txt")); err != nil {
		t.Fatal(err)
	} else if got, want := fi.Mode().Perm(), originalInfo.Mode().Perm(); got != want {
		t.Errorf("original existing.txt mode = %v; want unchanged %v", got, want)
	}

	// An open without O_CREATE gets the same answer for existing and absent
	// paths and does not touch the filesystem.
	for _, name := range []string{"existing.txt", "absent.txt"} {
		f, err := c.OpenFile(name, os.O_WRONLY)
		if err == nil {
			f.Close()
			t.Errorf("write-only open without create of %s succeeded", name)
			continue
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Errorf("write-only open without create of %s = %v; want permission denied", name, err)
		}
	}

	if err := writeFile(c, "drop.txt", "dropped"); err != nil {
		t.Fatalf("Create drop.txt: %v", err)
	}

	// A session may stat and adjust its latest upload through the requested
	// name, without learning the actual stored name.
	if _, err := c.Stat("drop.txt"); err != nil {
		t.Errorf("Stat own drop.txt: %v", err)
	}
	if err := c.Chmod("drop.txt", 0600); err != nil {
		t.Errorf("Chmod own drop.txt: %v", err)
	}
	if err := c.Mkdir("newdir"); err == nil {
		t.Error("Mkdir succeeded in flat write-only mode")
	}
	if _, err := c.Stat("/"); err != nil {
		t.Errorf("Stat /: %v", err)
	}
	if _, err := c.Stat("sub"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat sub = %v; want not-exist", err)
	}
	if err := writeFile(c, "sub/nested.txt", "nested"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Create sub/nested.txt = %v; want permission denied", err)
	}

	// Nothing else may be read, listed, stat'd, or modified.
	if got, err := readFile(c, "drop.txt"); err == nil {
		t.Errorf("read own drop.txt succeeded, got %q; want error (write-only)", got)
	}
	if got, err := readFile(c, "existing.txt"); err == nil {
		t.Errorf("read existing.txt succeeded, got %q; want error", got)
	}
	if _, err := c.ReadDir("/"); err == nil {
		t.Error("ReadDir succeeded in write-only mode")
	}
	if err := c.Remove("existing.txt"); err == nil {
		t.Error("Remove existing.txt succeeded in write-only mode")
	}
	if err := c.Rename("existing.txt", "renamed.txt"); err == nil {
		t.Error("Rename succeeded in write-only mode")
	}

	// A different session can't stat the first session's requested names.
	c2 := sftpClient(t, dir, tailcat.FileServeWO)
	if _, err := c2.Stat("drop.txt"); err == nil {
		t.Error("Stat drop.txt from a second session succeeded; want not-exist")
	}
}

func TestSFTPWriteOnlyPlus(t *testing.T) {
	dir := newServeDir(t)
	c := sftpClient(t, dir, tailcat.FileServeWOPlus)

	// The original name is preserved when free.
	if err := writeFile(c, "drop.txt", "first"); err != nil {
		t.Fatalf("Create drop.txt: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "drop.txt")); err != nil || string(got) != "first" {
		t.Fatalf("stored drop.txt = %q, %v; want first, nil", got, err)
	}

	// A collision is accepted under one server-chosen sibling name, without
	// overwriting the original.
	if err := writeFile(c, "drop.txt", "second"); err != nil {
		t.Fatalf("Create colliding drop.txt: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantName := regexp.MustCompile(`^drop\.[0-9]{14}\.[0-9a-f]{16}\.txt$`)
	var collisionName string
	for _, entry := range entries {
		if wantName.MatchString(entry.Name()) {
			collisionName = entry.Name()
		}
	}
	if collisionName == "" {
		t.Fatal("no timestamped collision file found")
	}
	if got, err := os.ReadFile(filepath.Join(dir, collisionName)); err != nil || string(got) != "second" {
		t.Errorf("collision file = %q, %v; want second, nil", got, err)
	}

	// Recursive mode exposes directories so uploads can resolve and create
	// directory trees.
	if _, err := c.Stat("sub"); err != nil {
		t.Errorf("Stat sub: %v", err)
	}
	if err := c.Mkdir("newdir"); err != nil {
		t.Fatalf("Mkdir newdir: %v", err)
	}
	if err := writeFile(c, "newdir/nested.txt", "nested"); err != nil {
		t.Fatalf("Create nested file: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "newdir", "nested.txt")); err != nil || string(got) != "nested" {
		t.Errorf("nested file = %q, %v; want nested, nil", got, err)
	}

	if _, err := c.ReadDir("/"); err == nil {
		t.Error("ReadDir succeeded in recursive write-only mode")
	}
	if got, err := readFile(c, "drop.txt"); err == nil {
		t.Errorf("read drop.txt succeeded, got %q", got)
	}
}

// TestSFTPSetstatTruncatedAttrs checks that a SETSTAT whose flags claim
// more attribute bytes than the packet contains gets a BAD_MESSAGE
// status rather than crashing the server. pkg/sftp's Request.Attributes
// returns nil for such packets, which setstat once dereferenced.
// sftp.Client can't send a malformed packet, so this writes raw
// SFTP v3 packets.
func TestSFTPSetstatTruncatedAttrs(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()
	go tailcat.ServeRootedSFTPForTest(srvConn, &tailcat.FileService{Dir: newServeDir(t), Mode: tailcat.FileServeRW})

	const (
		fxpInit      = 1
		fxpVersion   = 2
		fxpSetstat   = 9
		fxpStatus    = 101
		attrPerms    = 0x4 // SSH_FILEXFER_ATTR_PERMISSIONS
		fxBadMessage = 5   // SSH_FX_BAD_MESSAGE
		reqID        = 42
	)
	sendPacket := func(payload []byte) {
		t.Helper()
		pkt := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
		if _, err := cliConn.Write(append(pkt, payload...)); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	readPacket := func() []byte {
		t.Helper()
		var hdr [4]byte
		if _, err := io.ReadFull(cliConn, hdr[:]); err != nil {
			t.Fatalf("read packet length: %v", err)
		}
		payload := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(cliConn, payload); err != nil {
			t.Fatalf("read packet: %v", err)
		}
		return payload
	}

	sendPacket(binary.BigEndian.AppendUint32([]byte{fxpInit}, 3))
	if p := readPacket(); len(p) == 0 || p[0] != fxpVersion {
		t.Fatalf("got packet %x, want VERSION", p)
	}

	// The flags claim permissions follow, but the packet ends there.
	const path = "existing.txt"
	setstat := binary.BigEndian.AppendUint32([]byte{fxpSetstat}, reqID)
	setstat = binary.BigEndian.AppendUint32(setstat, uint32(len(path)))
	setstat = append(setstat, path...)
	setstat = binary.BigEndian.AppendUint32(setstat, attrPerms)
	sendPacket(setstat)

	p := readPacket()
	if len(p) < 9 || p[0] != fxpStatus {
		t.Fatalf("got packet %x, want STATUS", p)
	}
	if id := binary.BigEndian.Uint32(p[1:]); id != reqID {
		t.Errorf("status id = %d, want %d", id, reqID)
	}
	if code := binary.BigEndian.Uint32(p[5:]); code != fxBadMessage {
		t.Errorf("status code = %d, want %d (BAD_MESSAGE)", code, fxBadMessage)
	}
}
