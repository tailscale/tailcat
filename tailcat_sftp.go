// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package tailcat

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	ssh "github.com/tailscale/gliderssh"
)

// sftpServer is the part of sftp.Server and sftp.RequestServer the
// subsystem handler drives.
type sftpServer interface {
	Serve() error
	Close() error
}

// sftpSubsystemHandler returns the handler for the SSH "sftp"
// subsystem implied by opts, or nil if none should be registered.
func (s *Server) sftpSubsystemHandler(opts SSHOptions) ssh.SubsystemHandler {
	if opts.Files == nil && !opts.Shell {
		return nil
	}
	return func(sess ssh.Session) {
		var srv sftpServer
		if opts.Files != nil {
			rsrv, root, err := newRootedSFTPServer(sess, opts.Files)
			if err != nil {
				s.lb.logf("sftp session: %v", err)
				sess.Exit(1)
				return
			}
			defer root.Close()
			srv = rsrv
		} else {
			fsrv, err := newFullSFTPServer(sess)
			if err != nil {
				s.lb.logf("sftp session: %v", err)
				sess.Exit(1)
				return
			}
			srv = fsrv
		}
		err := srv.Serve()
		if errors.Is(err, io.EOF) {
			err = nil
		}
		// Exit must come before Close: Close closes the session
		// channel, and an exit-status sent after that is lost, making
		// scp report failure for successful transfers. Close still
		// runs afterwards to release any handles a client left open.
		if err != nil {
			s.lb.logf("sftp session: %v", err)
			sess.Exit(1)
		} else {
			sess.Exit(0)
		}
		srv.Close()
	}
}

// newFullSFTPServer returns an SFTP server for rwc with the same
// filesystem access a shell session has, for servers whose SSH
// already grants a shell. Relative paths resolve against the user's
// home directory, matching OpenSSH's sftp-server.
func newFullSFTPServer(rwc io.ReadWriteCloser) (*sftp.Server, error) {
	var opts []sftp.ServerOption
	if home, err := os.UserHomeDir(); err == nil {
		opts = append(opts, sftp.WithServerWorkingDirectory(home))
	}
	return sftp.NewServer(rwc, opts...)
}

// newRootedSFTPServer returns an SFTP server for rwc confined to
// fsrv.Dir with fsrv.Mode access, along with the os.Root confining
// it, which the caller must close after serving.
func newRootedSFTPServer(rwc io.ReadWriteCloser, fsrv *FileService) (*sftp.RequestServer, *os.Root, error) {
	root, err := os.OpenRoot(fsrv.Dir)
	if err != nil {
		return nil, nil, err
	}
	h := &rootedFiles{root: root, mode: fsrv.Mode}
	srv := sftp.NewRequestServer(rwc, sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	return srv, root, nil
}

// rootedFiles implements the pkg/sftp request handlers on top of an
// os.Root, enforcing a FileServeMode. One instance serves one SFTP
// session (one client connection).
type rootedFiles struct {
	root *os.Root
	mode FileServeMode

	mu sync.Mutex
	// wrote maps client-visible paths to the paths actually created by this
	// session. Drop-box modes use it for post-upload stats and setstats without
	// revealing server-chosen names.
	wrote map[string]string
}

// rel converts a cleaned absolute SFTP request path ("/foo/bar") to
// an os.Root-relative one ("foo/bar", or "." for the root itself).
func rel(requestPath string) string {
	p := strings.TrimPrefix(path.Clean(requestPath), "/")
	if p == "" {
		return "."
	}
	return p
}

// markOwn records that this session created requestedPath at actualPath.
func (h *rootedFiles) markOwn(requestedPath, actualPath string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wrote == nil {
		h.wrote = make(map[string]string)
	}
	h.wrote[requestedPath] = actualPath
}

// ownPath returns the actual path created for client-visible path p.
func (h *rootedFiles) ownPath(p string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	actual, ok := h.wrote[p]
	return actual, ok
}

func (h *rootedFiles) writeOnly() bool {
	return h.mode == FileServeWO || h.mode == FileServeWOPlus
}

// Fileread implements [sftp.FileReader] (the SFTP Get method).
func (h *rootedFiles) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if h.writeOnly() {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	return h.root.Open(rel(r.Filepath))
}

// Filewrite implements [sftp.FileWriter] (the SFTP Put and Open
// methods).
func (h *rootedFiles) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if h.mode == FileServeRO {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	pflags := r.Pflags()
	if h.writeOnly() {
		// A drop box only accepts creation of new files. Requiring the
		// client to ask for creation makes a plain write-only open fail
		// the same way whether its path exists or not; forcing exclusive
		// creation makes the no-overwrite check atomic.
		if pflags.Read || !pflags.Write || !pflags.Creat {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		requestedPath := rel(r.Filepath)
		if h.mode == FileServeWO && (requestedPath == "." || strings.Contains(requestedPath, "/")) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		actualPath := requestedPath
		var err error
		if h.mode == FileServeWO {
			actualPath, err = uniqueUploadPath(requestedPath)
			if err != nil {
				return nil, err
			}
		}
		f, err := h.root.OpenFile(actualPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if h.mode == FileServeWOPlus && errors.Is(err, os.ErrExist) {
			actualPath, err = uniqueUploadPath(requestedPath)
			if err != nil {
				return nil, err
			}
			f, err = h.root.OpenFile(actualPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		}
		if err != nil {
			return nil, err
		}
		h.markOwn(requestedPath, actualPath)
		return f, nil
	}
	flags := os.O_WRONLY
	if pflags.Read && pflags.Write {
		flags = os.O_RDWR
	}
	if pflags.Append {
		flags |= os.O_APPEND
	}
	if pflags.Creat {
		flags |= os.O_CREATE
	}
	if pflags.Trunc {
		flags |= os.O_TRUNC
	}
	if pflags.Excl {
		flags |= os.O_EXCL
	}
	p := rel(r.Filepath)
	f, err := h.root.OpenFile(p, flags, 0644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// uniqueUploadPath returns a server-chosen sibling of requestedPath. It uses
// enough randomness that OpenFile can make exactly one atomic O_EXCL attempt;
// a collision or random-source failure is returned rather than retried.
func uniqueUploadPath(requestedPath string) (string, error) {
	var random [8]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", err
	}
	base := path.Base(requestedPath)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	uniqueBase := stem + "." + time.Now().UTC().Format("20060102150405") + "." + hex.EncodeToString(random[:]) + ext
	if dir := path.Dir(requestedPath); dir != "." {
		return path.Join(dir, uniqueBase), nil
	}
	return uniqueBase, nil
}

// Filecmd implements [sftp.FileCmder] (the SFTP Setstat, Rename,
// Rmdir, Mkdir, Link, Symlink, and Remove methods).
func (h *rootedFiles) Filecmd(r *sftp.Request) error {
	p := rel(r.Filepath)
	switch h.mode {
	case FileServeRO:
		return sftp.ErrSSHFxPermissionDenied
	case FileServeWO, FileServeWOPlus:
		// A drop box lets a session adjust what it itself wrote (SFTP
		// clients commonly follow an upload with Setstat to fix up
		// permissions or times), but can't touch anything else. Only the
		// recursive mode accepts directories.
		switch r.Method {
		case "Mkdir":
			if h.mode == FileServeWO {
				return sftp.ErrSSHFxPermissionDenied
			}
			if err := h.root.Mkdir(p, 0755); err != nil {
				return err
			}
			h.markOwn(p, p)
			return nil
		case "Setstat":
			actualPath, ok := h.ownPath(p)
			if !ok {
				return sftp.ErrSSHFxPermissionDenied
			}
			return h.setstat(r, actualPath)
		}
		return sftp.ErrSSHFxPermissionDenied
	}
	switch r.Method {
	case "Setstat":
		return h.setstat(r, p)
	case "Rename":
		return h.root.Rename(p, rel(r.Target))
	case "Rmdir", "Remove":
		return h.root.Remove(p)
	case "Mkdir":
		return h.root.Mkdir(p, 0755)
	case "Link":
		// For Link and Symlink, Request.Filepath is the link target
		// and Request.Target is the new link's path.
		return h.root.Link(p, rel(r.Target))
	case "Symlink":
		return h.root.Symlink(p, rel(r.Target))
	}
	return sftp.ErrSSHFxOpUnsupported
}

// setstat applies the Setstat request r to the rooted path p.
func (h *rootedFiles) setstat(r *sftp.Request, p string) error {
	attrs := r.Attributes()
	if attrs == nil {
		// Attributes returns nil if the packet is shorter than its
		// attribute flags claim. Without this check, a malformed
		// request from the client would crash the server.
		return sftp.ErrSSHFxBadMessage
	}
	flags := r.AttrFlags()
	// UidGid is deliberately ignored: the tunnel is identity-free, so
	// client uid/gid numbers are meaningless here.
	if flags.Permissions {
		if err := h.root.Chmod(p, os.FileMode(attrs.Mode).Perm()); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		if err := h.root.Chtimes(p, atime, mtime); err != nil {
			return err
		}
	}
	if flags.Size {
		f, err := h.root.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		err = f.Truncate(int64(attrs.Size))
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Filelist implements [sftp.FileLister] (the SFTP List and Stat
// methods; Lstat and Readlink have dedicated methods below).
func (h *rootedFiles) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	p := rel(r.Filepath)
	switch r.Method {
	case "List":
		if h.writeOnly() {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		f, err := h.root.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		fis, err := f.Readdir(0)
		if err != nil {
			return nil, err
		}
		return listerAt(fis), nil
	case "Stat":
		fi, err := h.stat(p, h.root.Stat)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

// Lstat implements [sftp.LstatFileLister].
func (h *rootedFiles) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	fi, err := h.stat(rel(r.Filepath), h.root.Lstat)
	if err != nil {
		return nil, err
	}
	return listerAt{fi}, nil
}

// Readlink implements [sftp.ReadlinkFileLister].
func (h *rootedFiles) Readlink(requestPath string) (string, error) {
	if h.writeOnly() {
		return "", sftp.ErrSSHFxPermissionDenied
	}
	return h.root.Readlink(rel(requestPath))
}

// stat stats the rooted path p with statf, applying the drop-box visibility
// policy. Both modes expose paths this session created. Strict write-only mode
// otherwise exposes only the root; write-only-plus also exposes directories so
// recursive upload destinations can resolve.
func (h *rootedFiles) stat(p string, statf func(string) (os.FileInfo, error)) (os.FileInfo, error) {
	if !h.writeOnly() {
		return statf(p)
	}
	if actualPath, ok := h.ownPath(p); ok {
		return statf(actualPath)
	}
	if h.mode == FileServeWO && p != "." {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	fi, err := statf(p)
	if err != nil || !fi.IsDir() {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	return fi, nil
}

// listerAt adapts a []os.FileInfo to [sftp.ListerAt].
type listerAt []os.FileInfo

func (l listerAt) ListAt(dst []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[off:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}
