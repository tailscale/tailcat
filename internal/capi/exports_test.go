// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestExportsInSync asserts that cmd/libtailcat's three descriptions
// of the C ABI agree: the //export directives in main.go (what the
// shared library actually exports), the prototypes in tailcat.h (what
// C callers compile against), and libtailcat.def (from which MSVC
// users build an import library with lib /def:). The files are read
// as plain text, like internal/buildtags does for build-tags.txt.
func TestExportsInSync(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("../../cmd/libtailcat/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	names := func(text string, re *regexp.Regexp) []string {
		var out []string
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, m[1])
		}
		slices.Sort(out)
		return out
	}

	exports := names(read("main.go"), regexp.MustCompile(`(?m)^//export (tc_\w+)$`))
	if len(exports) == 0 {
		t.Fatal("found no //export directives in main.go")
	}
	if dup := slices.Compact(slices.Clone(exports)); len(dup) != len(exports) {
		t.Errorf("main.go exports contain duplicates: %v", exports)
	}

	header := names(read("tailcat.h"), regexp.MustCompile(`(?m)^(?:u?int32_t|void) (tc_\w+)\(`))
	if !slices.Equal(header, exports) {
		t.Errorf("tailcat.h prototypes do not match main.go exports\n got: %v\nwant: %v", header, exports)
	}

	def := read("libtailcat.def")
	_, body, ok := strings.Cut(def, "\nEXPORTS\n")
	if !ok {
		t.Fatal("libtailcat.def has no EXPORTS section")
	}
	var listed []string
	for _, line := range strings.Split(body, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, ";") {
			listed = append(listed, line)
		}
	}
	if !slices.Equal(listed, exports) {
		t.Errorf("libtailcat.def EXPORTS do not match main.go exports (list them sorted, one per line)\n got: %v\nwant: %v", listed, exports)
	}
}
