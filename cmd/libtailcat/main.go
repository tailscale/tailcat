// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command libtailcat exports Tailcat through a versioned, C-compatible ABI.
package main

/*
#include "tailcat.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"runtime/debug"
	"unsafe"

	"github.com/tailscale/tailcat/internal/capi"
)

func main() {}

func guard(out **C.char, fn func() error) (code C.int32_t) {
	if out != nil {
		*out = nil
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "libtailcat: internal failure: %v\n%s", r, debug.Stack())
			code = C.int32_t(capi.Failure)
			if out != nil {
				*out = C.CString(fmt.Sprintf("internal tailcat failure: %v", r))
			}
		}
	}()
	if err := fn(); err != nil {
		if out != nil {
			*out = C.CString(err.Error())
		}
		return C.int32_t(capi.ErrorCode(err))
	}
	return 0
}

func handle(out *C.tc_handle, fn func() (capi.Handle, error)) error {
	if out == nil {
		return capi.ErrArgument
	}
	*out = 0
	h, err := fn()
	if err == nil {
		*out = C.tc_handle(h)
	}
	return err
}

func text(out **C.char, fn func() (string, error)) error {
	if out == nil {
		return capi.ErrArgument
	}
	*out = nil
	s, err := fn()
	if err == nil {
		*out = C.CString(s)
	}
	return err
}

//export tc_abi_version
func tc_abi_version() C.uint32_t { return capi.ABIVersion }

//export tc_build_info
func tc_build_info(out, err **C.char) C.int32_t {
	return guard(err, func() error { return text(out, func() (string, error) { return capi.BuildInfo(), nil }) })
}

//export tc_token_new
func tc_token_new(ns C.int64_t, out *C.tc_token, err **C.char) C.int32_t {
	return guard(err, func() error { return handle(out, func() (capi.Handle, error) { return capi.NewToken(int64(ns)) }) })
}

//export tc_token_cancel
func tc_token_cancel(token C.tc_token, err **C.char) C.int32_t {
	return guard(err, func() error { return capi.Cancel(capi.Handle(token)) })
}

//export tc_close
func tc_close(id C.tc_handle, err **C.char) C.int32_t {
	return guard(err, func() error { return capi.Close(capi.Handle(id)) })
}

//export tc_free
func tc_free(ptr unsafe.Pointer) { C.free(ptr) }

//export tc_client_new
func tc_client_new(config *C.char, out *C.tc_handle, err **C.char) C.int32_t {
	return guard(err, func() error {
		return handle(out, func() (capi.Handle, error) { return capi.NewClient(C.GoString(config)) })
	})
}

//export tc_server_new
func tc_server_new(config *C.char, out *C.tc_handle, err **C.char) C.int32_t {
	return guard(err, func() error {
		return handle(out, func() (capi.Handle, error) { return capi.NewServer(C.GoString(config)) })
	})
}

//export tc_client_dial
func tc_client_dial(id C.tc_handle, token C.tc_token, port C.uint16_t, network C.int32_t, out *C.tc_handle, err **C.char) C.int32_t {
	return guard(err, func() error {
		return handle(out, func() (capi.Handle, error) {
			return capi.Dial(capi.Handle(id), capi.Handle(token), uint16(port), int(network))
		})
	})
}

//export tc_server_start
func tc_server_start(id C.tc_handle, token C.tc_token, err **C.char) C.int32_t {
	return guard(err, func() error { return capi.Start(capi.Handle(id), capi.Handle(token)) })
}

//export tc_server_listen
func tc_server_listen(id C.tc_handle, token C.tc_token, port C.uint16_t, network C.int32_t, out *C.tc_handle, err **C.char) C.int32_t {
	return guard(err, func() error {
		return handle(out, func() (capi.Handle, error) {
			return capi.Listen(capi.Handle(id), capi.Handle(token), uint16(port), int(network))
		})
	})
}

//export tc_listener_accept
func tc_listener_accept(id C.tc_handle, token C.tc_token, out *C.tc_handle, err **C.char) C.int32_t {
	return guard(err, func() error {
		return handle(out, func() (capi.Handle, error) { return capi.Accept(capi.Handle(id), capi.Handle(token)) })
	})
}

func buffer(ptr unsafe.Pointer, n C.size_t) ([]byte, error) {
	if uint64(n) > uint64(^uint(0)>>1) || (ptr == nil && n != 0) {
		return nil, capi.ErrArgument
	}
	return unsafe.Slice((*byte)(ptr), int(n)), nil
}

//export tc_conn_read
func tc_conn_read(id C.tc_handle, token C.tc_token, ptr unsafe.Pointer, size C.size_t, count *C.size_t, err **C.char) C.int32_t {
	return guard(err, func() error {
		if count == nil {
			return capi.ErrArgument
		}
		*count = 0
		b, err := buffer(ptr, size)
		if err != nil {
			return err
		}
		n, err := capi.Read(capi.Handle(id), capi.Handle(token), b)
		*count = C.size_t(n)
		return err
	})
}

//export tc_conn_write
func tc_conn_write(id C.tc_handle, token C.tc_token, ptr unsafe.Pointer, size C.size_t, count *C.size_t, err **C.char) C.int32_t {
	return guard(err, func() error {
		if count == nil {
			return capi.ErrArgument
		}
		*count = 0
		b, err := buffer(ptr, size)
		if err != nil {
			return err
		}
		n, err := capi.Write(capi.Handle(id), capi.Handle(token), b)
		*count = C.size_t(n)
		return err
	})
}

//export tc_conn_close_write
func tc_conn_close_write(id C.tc_handle, token C.tc_token, err **C.char) C.int32_t {
	return guard(err, func() error { return capi.CloseWrite(capi.Handle(id), capi.Handle(token)) })
}

//export tc_conn_readable
func tc_conn_readable(id C.tc_handle, out *C.int32_t, err **C.char) C.int32_t {
	return guard(err, func() error {
		if out == nil {
			return capi.ErrArgument
		}
		*out = 0
		ready, err := capi.Readable(capi.Handle(id))
		if ready {
			*out = 1
		}
		return err
	})
}

//export tc_info
func tc_info(id C.tc_handle, token C.tc_token, out, err **C.char) C.int32_t {
	return guard(err, func() error {
		return text(out, func() (string, error) { return capi.Info(capi.Handle(id), capi.Handle(token)) })
	})
}

//export tc_client_ping
func tc_client_ping(id C.tc_handle, token C.tc_token, pingMS *C.int32_t, err **C.char) C.int32_t {
	return guard(err, func() error {
		if pingMS == nil {
			return capi.ErrArgument
		}
		*pingMS = 0
		ms, err := capi.Ping(capi.Handle(id), capi.Handle(token))
		if err == nil {
			*pingMS = C.int32_t(ms)
		}
		return err
	})
}

//export tc_client_disco_ping
func tc_client_disco_ping(id C.tc_handle, token C.tc_token, out, err **C.char) C.int32_t {
	return guard(err, func() error {
		return text(out, func() (string, error) { return capi.DiscoPing(capi.Handle(id), capi.Handle(token)) })
	})
}

//export tc_server_allow_client
func tc_server_allow_client(id C.tc_handle, token C.tc_token, pub *C.char, err **C.char) C.int32_t {
	return guard(err, func() error { return capi.AllowClient(capi.Handle(id), capi.Handle(token), C.GoString(pub)) })
}

//export tc_drain
func tc_drain(id C.tc_handle, token C.tc_token, err **C.char) C.int32_t {
	return guard(err, func() error { return capi.Drain(capi.Handle(id), capi.Handle(token)) })
}

//export tc_address_parse
func tc_address_parse(addr *C.char, out, err **C.char) C.int32_t {
	return guard(err, func() error { return text(out, func() (string, error) { return capi.ParseAddress(C.GoString(addr)) }) })
}

//export tc_address_resolve
func tc_address_resolve(token C.tc_token, addr, mapURL *C.char, out, err **C.char) C.int32_t {
	return guard(err, func() error {
		return text(out, func() (string, error) {
			return capi.ResolveAddress(capi.Handle(token), C.GoString(addr), C.GoString(mapURL))
		})
	})
}

//export tc_key_generate
func tc_key_generate(out, err **C.char) C.int32_t {
	return guard(err, func() error { return text(out, capi.GenerateKey) })
}
