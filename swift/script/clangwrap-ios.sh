#!/bin/sh
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# cgo CC wrapper for iOS devices (arm64).

SDK=iphoneos
PLATFORM=ios

CLANGARCH="arm64"

SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`

# cmd/cgo doesn't support llvm-gcc-4.2, so we have to use clang.
CLANG=`xcrun --sdk $SDK --find clang`

exec "$CLANG" -arch $CLANGARCH -isysroot "$SDK_PATH" -m${PLATFORM}-version-min=17.0 "$@"
