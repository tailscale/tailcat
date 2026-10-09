// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_ssh

package main

import (
	"context"
	"errors"

	"github.com/peterbourgon/ff/v4"
)

const tailCatSSHEnabled = false

func loadSSHAuthorizedKeys(context.Context, string) ([]string, error) {
	return nil, errors.New("SSH support not compiled in")
}

// sshCommand returns a stub "tailcat ssh" subcommand that only
// reports that SSH support was omitted from this build.
func sshCommand(parent *ff.FlagSet) *ff.Command {
	return &ff.Command{
		Name:      "ssh",
		Usage:     "tailcat ssh",
		ShortHelp: "(SSH support not included in this build)",
		Flags:     ff.NewFlagSet("ssh").SetParent(parent),
		Exec: func(ctx context.Context, args []string) error {
			return errors.New("ssh support not compiled in")
		},
	}
}

// cpCommand returns a stub "tailcat cp" subcommand that only reports
// that SSH support was omitted from this build.
func cpCommand(parent *ff.FlagSet) *ff.Command {
	return &ff.Command{
		Name:      "cp",
		Usage:     "tailcat cp",
		ShortHelp: "(SSH support not included in this build)",
		Flags:     ff.NewFlagSet("cp").SetParent(parent),
		Exec: func(ctx context.Context, args []string) error {
			return errors.New("ssh support not compiled in")
		},
	}
}

// lsCommand returns a stub "tailcat ls" subcommand that only reports
// that SSH support was omitted from this build.
func lsCommand(parent *ff.FlagSet) *ff.Command {
	return &ff.Command{
		Name:      "ls",
		Usage:     "tailcat ls",
		ShortHelp: "(SSH support not included in this build)",
		Flags:     ff.NewFlagSet("ls").SetParent(parent),
		Exec: func(ctx context.Context, args []string) error {
			return errors.New("ssh support not compiled in")
		},
	}
}
