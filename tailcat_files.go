// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

// This file is intentionally free of build tags: it declares the
// types [Server.SSHConnHandler] takes, so code can name them on
// platforms where the SSH server itself is compiled out.

// FileServeMode says what a rooted SFTP file service lets clients do.
type FileServeMode byte

const (
	// FileServeRO serves files read-only: clients can list, stat, and
	// download files, but not modify anything.
	FileServeRO FileServeMode = iota

	// FileServeRW serves files read-write.
	FileServeRW

	// FileServeWO serves files write-only, as a flat drop box. Each upload
	// is stored under a new, server-chosen name, so clients can't use name
	// collisions to discover existing files. Clients can't make directories,
	// list the drop box, or read anything back.
	FileServeWO

	// FileServeWOPlus serves files write-only, as a recursive drop box.
	// Clients can make and stat directories, which necessarily reveals some
	// information about existing paths. An upload keeps its requested name
	// when available and is stored under a new, server-chosen name otherwise.
	FileServeWOPlus
)

// FileService describes a rooted SFTP file service. All client paths
// are resolved inside Dir via [os.Root], so neither ".." nor symlinks
// can escape it.
type FileService struct {
	// Dir is the directory to serve.
	Dir string

	// Mode says what clients may do within Dir.
	Mode FileServeMode
}

// SSHOptions configures the SSH server returned by
// [Server.SSHConnHandler].
type SSHOptions struct {
	// Shell enables shell and exec sessions.
	Shell bool

	// AuthorizedKeys contains OpenSSH authorized_keys text. Each element may
	// contain one or more public key lines. Clients authenticate with one of the
	// listed keys. Authorized-key options are not supported; rejecting them
	// avoids silently granting broader access than their author intended.
	AuthorizedKeys []string

	// Files, if non-nil, serves the SFTP subsystem rooted at
	// Files.Dir, restricted to Files.Mode. If nil and Shell is true,
	// SFTP is instead served with the same access the shell has: the
	// whole filesystem, with relative paths resolved against the
	// user's home directory.
	Files *FileService
}
