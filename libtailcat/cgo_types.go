// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && cgo

package main

// Go doesn't allow cgo in _test.go files, so the C types, constants and
// helpers that libtailcat_test.go needs to call the exported functions
// are given Go names here. Nothing else uses them.

/*
#include <errno.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

type (
	cChar   = C.char
	cInt    = C.int
	cSize   = C.size_t
	cDouble = C.double
)

const (
	cEBADF  = C.EBADF
	cERANGE = C.ERANGE
)

// cString returns s as a malloc'd C string; free it with cFree.
func cString(s string) *C.char { return C.CString(s) }

// cFree releases a malloc'd C string.
func cFree(p *C.char) { C.free(unsafe.Pointer(p)) }

// goString copies the C string p into a Go string.
func goString(p *C.char) string { return C.GoString(p) }
