# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

export CGO_ENABLED=1

# The library targets are phony so that source changes always
# rebuild them; Go's build cache keeps that cheap.
.PHONY: libtailcat.a libtailcat.so

libtailcat.a: ## Build the static c-archive library
	go build -buildmode=c-archive -o $@

libtailcat.so: ## Build the shared c-shared library
	go build -buildmode=c-shared -o $@

.PHONY: c-archive
c-archive: libtailcat.a

.PHONY: shared
shared: libtailcat.so

.PHONY: all
all: c-archive shared

.PHONY: clean
clean: ## Remove build artifacts, including the cgo-generated header
	rm -f libtailcat.h libtailcat.a libtailcat.so

.DEFAULT_GOAL := all
