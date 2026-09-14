# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# Builds libtailcat as Go c-archives for macOS (arm64 + x86_64), iOS
# devices (arm64) and the iOS simulator (arm64 + x86_64), and packages
# them with include/ as ../swift/CTailcat.xcframework.
#
# Every archive is built with the release build tags from
# ../build-tags.txt, which trim the tailscale.com dependency down to
# what tailcat needs.

GO ?= go
TAGS := $(shell cat ../build-tags.txt)
BUILD := build
SCRIPT := $(abspath script)
XCFRAMEWORK := ../swift/CTailcat.xcframework

# `?=` so the environment can override them.
MACOS_TARGET ?= 14.0

export CGO_ENABLED = 1
export MACOS_TARGET

.PHONY: all
all: xcframework ## Builds everything (the default)

$(BUILD):
	mkdir -p $(BUILD)

# macOS: arm64 natively, x86_64 through the clang wrapper, then lipo.
.PHONY: macos
macos: $(BUILD) ## Builds the fat macOS archive build/libtailcat_macos.a
	MACOSX_DEPLOYMENT_TARGET=$(MACOS_TARGET) GOOS=darwin GOARCH=arm64 \
		CGO_CFLAGS="-mmacos-version-min=$(MACOS_TARGET)" CGO_LDFLAGS="-mmacos-version-min=$(MACOS_TARGET)" \
		$(GO) build -buildmode=c-archive -tags "$(TAGS)" -ldflags "-s -w" -o $(BUILD)/libtailcat_macos_arm64.a .
	MACOSX_DEPLOYMENT_TARGET=$(MACOS_TARGET) GOOS=darwin GOARCH=amd64 CC=$(SCRIPT)/clangwrap-macos-x86.sh \
		$(GO) build -buildmode=c-archive -tags "$(TAGS)" -ldflags "-s -w" -o $(BUILD)/libtailcat_macos_x86_64.a .
	lipo -create -output $(BUILD)/libtailcat_macos.a $(BUILD)/libtailcat_macos_arm64.a $(BUILD)/libtailcat_macos_x86_64.a

.PHONY: ios
ios: $(BUILD) ## Builds the iOS device archive build/libtailcat_ios.a (iOS SDK required)
	GOOS=ios GOARCH=arm64 CC=$(SCRIPT)/clangwrap-ios.sh \
		$(GO) build -buildmode=c-archive -tags "ios,$(TAGS)" -ldflags -w -o $(BUILD)/libtailcat_ios.a .

.PHONY: ios-sim
ios-sim: $(BUILD) ## Builds the fat iOS simulator archive build/libtailcat_iossim.a (iOS SDK required)
	GOOS=ios GOARCH=arm64 CC=$(SCRIPT)/clangwrap-ios-sim-arm.sh \
		$(GO) build -buildmode=c-archive -tags "ios,$(TAGS)" -ldflags -w -o $(BUILD)/libtailcat_iossim_arm64.a .
	GOOS=ios GOARCH=amd64 CC=$(SCRIPT)/clangwrap-ios-sim-x86.sh \
		$(GO) build -buildmode=c-archive -tags "ios,$(TAGS)" -ldflags -w -o $(BUILD)/libtailcat_iossim_x86_64.a .
	lipo -create -output $(BUILD)/libtailcat_iossim.a $(BUILD)/libtailcat_iossim_arm64.a $(BUILD)/libtailcat_iossim_x86_64.a

.PHONY: xcframework
xcframework: macos ios ios-sim ## Builds ../swift/CTailcat.xcframework from the three archives
	rm -rf $(XCFRAMEWORK)
	mkdir -p $(dir $(XCFRAMEWORK))
	xcodebuild -create-xcframework \
		-library $(BUILD)/libtailcat_macos.a -headers include \
		-library $(BUILD)/libtailcat_ios.a -headers include \
		-library $(BUILD)/libtailcat_iossim.a -headers include \
		-output $(XCFRAMEWORK)

.PHONY: test
test: ## Runs the offline Go tests of the exported functions
	cd .. && $(GO) test ./libtailcat/ -run . -count=1

.PHONY: clean
clean: ## Removes build/ and the xcframework
	rm -rf $(BUILD) $(XCFRAMEWORK)

.PHONY: help
help: ## Shows this help
	@printf '\nSpecify a target. The choices are:\n\n'
	@grep -hE '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
	@printf '\n'
