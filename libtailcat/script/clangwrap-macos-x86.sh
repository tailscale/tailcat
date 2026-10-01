#!/bin/sh
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# cgo CC wrapper for cross-compiling the macOS x86_64 slice on any Mac.
# MACOS_TARGET, exported by the Makefile, is the minimum macOS version.

SDK=macosx

SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`

# cmd/cgo doesn't support llvm-gcc-4.2, so we have to use clang.
CLANG=`xcrun --sdk $SDK --find clang`

exec "$CLANG" -arch x86_64 -target x86_64-apple-macos${MACOS_TARGET:-14.0} -isysroot "$SDK_PATH" "$@"
