// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/tailcat/internal/buildtags"
	"tailscale.com/tstest/integration"
)

var (
	buildOnce sync.Once
	buildErr  error
	// builtBin describes the built binary. Its Path is in the building
	// test's TempDir and may be gone by the time a later test runs, but
	// its FD (or Contents on Windows) stays usable; see CopyTo.
	builtBin    integration.BinaryInfo
	builtBinDir string
)

// buildTailcat returns the path of a tailcat binary built with the
// same build tags official releases use, so the end-to-end tests
// exercise the released feature set. (The test harness itself must
// stay untagged: the tailscale.com test-only dependencies do not
// compile under the release omit tags, so only the child binary under
// test gets them.)
//
// The binary is built once per test process, into the first calling
// test's TempDir so the testing framework cleans it up even when
// tests fail; later tests get it hardlinked or copied into their own
// TempDirs via integration.BinaryInfo.CopyTo.
func buildTailcat(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	buildOnce.Do(func() { buildErr = buildTailcatBinary(dir) })
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	if dir == builtBinDir {
		return builtBin.Path
	}
	bi, err := builtBin.CopyTo(dir)
	if err != nil {
		t.Fatal(err)
	}
	return bi.Path
}

// buildTailcatBinary builds the release-tagged tailcat binary into
// dir and initializes builtBin and builtBinDir.
func buildTailcatBinary(dir string) error {
	bin := filepath.Join(dir, "tailcat")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-tags", buildtags.ReleaseTags(), "-o", bin, ".").CombinedOutput(); err != nil {
		return fmt.Errorf("build: %v\n%s", err, out)
	}
	fi, err := os.Stat(bin)
	if err != nil {
		return err
	}
	bi := integration.BinaryInfo{Path: bin, Size: fi.Size()}
	if runtime.GOOS == "windows" {
		bi.Contents, err = os.ReadFile(bin)
		if err != nil {
			return err
		}
	} else {
		// The FD is deliberately never closed: it keeps the binary's
		// inode alive for CopyTo after this test's TempDir is deleted,
		// and the process exit closes it.
		bi.FD, err = os.OpenFile(bin, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		bi.FDMu = new(sync.Mutex)
	}
	builtBin = bi
	builtBinDir = dir
	return nil
}

// TestVersionFlag verifies that "tailcat --version" works even though
// --version is not a registered flag; main special-cases it on parse
// failure. The advertised interface is the version subcommand, but
// nixpkgs' versionCheckHook runs "tailcat --version" and depends on
// its exit status and output.
func TestVersionFlag(t *testing.T) {
	t.Parallel()
	bin := buildTailcat(t)
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("tailcat --version: %v\n%s", err, out)
	}
	if v := strings.TrimSpace(string(out)); v == "" || strings.Contains(v, "\n") {
		t.Errorf("output = %q; want a single non-empty version line", out)
	}
}

// testNoopCommand returns a child command that exits successfully,
// for tests that only care that a wrapper ran it. Windows has no
// "true" binary.
func testNoopCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/d", "/c", "exit", "/b", "0"}
	}
	return []string{"true"}
}

// cacheEnv returns environment variables that point os.UserCacheDir
// at a temp dir on all operating systems, so test runs don't litter
// the real user cache with DERP map entries keyed by a test's
// ephemeral --derpmap-url. Pointing HOME at the temp dir also keeps
// SSH state (the server's generated host key under os.UserConfigDir
// and the client's ~/.ssh) out of the real home directory.
func cacheEnv(t *testing.T) []string {
	dir := t.TempDir()
	return []string{
		"XDG_CACHE_HOME=" + dir, // Linux
		"HOME=" + dir,           // macOS
		"LocalAppData=" + dir,   // Windows os.UserCacheDir
		"AppData=" + dir,        // Windows os.UserConfigDir (SSH host key)
	}
}

// lockedBuf is a bytes.Buffer safe for concurrent use, so tests can
// read a child process's output while the process is still writing
// it.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitAddr polls addrFile every 100ms for up to 30 seconds and
// returns the trimmed tailcat address a tailcat server wrote there via
// TAILCAT_ADDR_FILE. On timeout it fails the test, including the
// server's stderr.
func waitAddr(t *testing.T, addrFile string, stderr *lockedBuf) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for addr file; server stderr:\n%s", stderr.String())
		}
		b, err := os.ReadFile(addrFile)
		if err == nil && len(b) > 0 {
			addr := strings.TrimSpace(string(b))
			t.Logf("server addr: %s", addr)
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// skipIfNixSandbox skips tests that have been observed to flake in
// the no-network Nix build sandbox, so that rare flakes don't block
// nix flake and nixpkgs builds. The tests still run everywhere else,
// including GitHub CI.
func skipIfNixSandbox(t *testing.T) {
	t.Helper()
	if os.Getenv("NIX_BUILD_TOP") != "" {
		t.Skip("skipping known-flaky test in the Nix build sandbox")
	}
}

// waitForLog polls buf every 10ms until it contains want, failing t
// after 30 seconds. A child process's output reaches buf through a
// pipe copied by a goroutine, so it can trail other readiness signals
// (like the addr file); tests must poll rather than assert on buf's
// contents at a point in time.
func waitForLog(t *testing.T, buf *lockedBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(buf.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for log output %q; got:\n%s", want, buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// testEnv is a hermetic environment for CLI end-to-end tests: a
// localhost DERP+STUN server, an httptest server serving its DERP map
// JSON, and environment variables pointing the binary's caches at
// temp dirs.
type testEnv struct {
	t          *testing.T
	bin        string
	derpMapURL string
	env        []string
}

// newTestEnv builds the tailcat binary and starts the DERP+STUN and
// DERP map servers, all cleaned up with the test.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	bin := buildTailcat(t)

	dm := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")
	dmJSON, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	dmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dmJSON)
	}))
	t.Cleanup(dmSrv.Close)

	return &testEnv{
		t:          t,
		bin:        bin,
		derpMapURL: dmSrv.URL,
		env:        append(os.Environ(), cacheEnv(t)...),
	}
}

// cmd returns an unstarted command running the tailcat binary with
// the test cache environment. Callers pass all flags explicitly,
// including --derpmap-url=e.derpMapURL where needed.
func (e *testEnv) cmd(args ...string) *exec.Cmd {
	cmd := exec.Command(e.bin, args...)
	cmd.Env = e.env
	return cmd
}

// serverCmd returns an unstarted server-mode command with the given
// extra flags and the addr file path its TAILCAT_ADDR_FILE points at,
// so callers can wire up pipes before starting it.
func (e *testEnv) serverCmd(extraFlags ...string) (*exec.Cmd, string) {
	addrFile := filepath.Join(e.t.TempDir(), "addr")
	args := append([]string{"--key=new", "--derpmap-url=" + e.derpMapURL}, extraFlags...)
	cmd := e.cmd(args...)
	cmd.Env = append(cmd.Env, "TAILCAT_ADDR_FILE="+addrFile)
	return cmd, addrFile
}

// startServer starts a tailcat server with the given extra flags,
// arranges for it to be killed when the test ends, waits for its
// tailcat address, and returns the running command, the addr, and the
// server's captured stderr.
func (e *testEnv) startServer(extraFlags ...string) (*exec.Cmd, string, *lockedBuf) {
	e.t.Helper()
	server, addrFile := e.serverCmd(extraFlags...)
	var stderr lockedBuf
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { server.Process.Kill() })
	addr := waitAddr(e.t, addrFile, &stderr)
	return server, addr, &stderr
}
