// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestReleaseArchiveAsset(t *testing.T) {
	tests := []struct {
		name, version, goos, goarch, goarm, want string
	}{
		{"linux-amd64", "v0.2.0", "linux", "amd64", "", "tailcat_0.2.0_linux_amd64.tar.gz"},
		{"linux-arm64", "v0.2.0", "linux", "arm64", "", "tailcat_0.2.0_linux_arm64.tar.gz"},
		{"linux-armv7", "v0.2.0", "linux", "arm", "7", "tailcat_0.2.0_linux_armv7.tar.gz"},
		{"linux-armv6-hardfloat", "v1.12.3", "linux", "arm", "6,hardfloat", "tailcat_1.12.3_linux_armv6.tar.gz"},
		{"windows-amd64", "v1.2.3", "windows", "amd64", "", "tailcat_1.2.3_windows_amd64.zip"},
		{"windows-arm64", "v1.2.3", "windows", "arm64", "", "tailcat_1.2.3_windows_arm64.zip"},
		{"future-darwin-amd64", "v1.2.3", "darwin", "amd64", "", "tailcat_1.2.3_darwin_amd64.tar.gz"},
		{"future-darwin-arm64", "v1.2.3", "darwin", "arm64", "", "tailcat_1.2.3_darwin_arm64.tar.gz"},
		{"future-freebsd-riscv64", "v1.2.3", "freebsd", "riscv64", "", "tailcat_1.2.3_freebsd_riscv64.tar.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel := githubRelease{TagName: tt.version, Assets: []releaseAsset{{Name: "checksums.txt"}, {Name: tt.want}}}
			got, err := releaseArchiveAsset(rel, tt.goos, tt.goarch, tt.goarm)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tt.want {
				t.Fatalf("releaseArchiveAsset = %q, want %q", got.Name, tt.want)
			}
		})
	}

	missing := githubRelease{TagName: "v1.2.3"}
	if _, err := releaseArchiveAsset(missing, "darwin", "arm64", ""); err == nil {
		t.Fatal("missing platform archive unexpectedly succeeded")
	}
	ambiguous := githubRelease{TagName: "v1.2.3", Assets: []releaseAsset{
		{Name: "tailcat_1.2.3_darwin_arm64.tar.gz"},
		{Name: "tailcat_1.2.3_darwin_arm64.zip"},
	}}
	if _, err := releaseArchiveAsset(ambiguous, "darwin", "arm64", ""); err == nil {
		t.Fatal("ambiguous platform archives unexpectedly succeeded")
	}
	if _, err := releaseArchiveBase("v1.2.3", "../darwin", "arm64", ""); err == nil {
		t.Fatal("unsafe platform component unexpectedly succeeded")
	}
}

func TestCompareReleaseVersions(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
	}{
		{"v0.2.0", "v0.2.0", 0},
		{"v0.2.0", "v0.10.0", -1},
		{"v2.0.0", "v1.99.99", 1},
	} {
		if got := compareReleaseVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareReleaseVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestRunWithLockReleasesLockOnError(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "update.lock")
	u := &updater{
		lockPath: func() (string, error) { return lockPath, nil },
	}
	if _, err := u.runWithLock(context.Background(), "(devel)"); err == nil {
		t.Fatal("development build unexpectedly updated")
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("update lock remains after error: %v", err)
	}

	releaseLock, acquired, err := u.acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("could not reacquire update lock after error")
	}
	releaseLock()
}

func TestChecksumForAsset(t *testing.T) {
	want := sha256.Sum256([]byte("archive"))
	checksums := fmt.Appendf(nil, "%x  other.zip\n%x *tailcat.zip\n", sha256.Sum256(nil), want)
	got, err := checksumForAsset(checksums, "tailcat.zip")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("checksum = %x, want %x", got, want)
	}
	if _, err := checksumForAsset(checksums, "missing.zip"); err == nil {
		t.Fatal("missing checksum unexpectedly succeeded")
	}
	duplicate := append(append([]byte(nil), checksums...), fmt.Appendf(nil, "%x  tailcat.zip\n", want)...)
	if _, err := checksumForAsset(duplicate, "tailcat.zip"); err == nil {
		t.Fatal("duplicate checksum unexpectedly succeeded")
	}
}

func TestUniqueReleaseAssetRejectsDuplicates(t *testing.T) {
	assets := []releaseAsset{{Name: "tailcat.zip"}, {Name: "tailcat.zip"}}
	if _, err := uniqueReleaseAsset(assets, "tailcat.zip"); err == nil {
		t.Fatal("duplicate release asset unexpectedly succeeded")
	}
}

func TestExtractReleaseBinary(t *testing.T) {
	const want = "new tailcat binary"
	zipBytes := testZIP(t, "tailcat.exe", []byte(want))
	got, err := extractReleaseBinary("tailcat_1.0.0_windows_amd64.zip", zipBytes, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("ZIP binary = %q, want %q", got, want)
	}

	tarBytes := testTarGz(t, "tailcat", []byte(want))
	got, err = extractReleaseBinary("tailcat_1.0.0_linux_amd64.tar.gz", tarBytes, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("tar binary = %q, want %q", got, want)
	}

	nested := testZIP(t, "bin/tailcat.exe", []byte(want))
	if _, err := extractReleaseBinary("tailcat.zip", nested, "windows"); err == nil {
		t.Fatal("nested executable unexpectedly accepted")
	}
}

func TestUpdaterRun(t *testing.T) {
	const (
		currentVersion = "v0.1.0"
		latestVersion  = "v0.2.0"
		newBinary      = "new tailcat binary"
	)
	tests := []struct {
		name, goos, goarch, goarm, archiveName, binaryName string
	}{
		{"linux-amd64", "linux", "amd64", "", "tailcat_0.2.0_linux_amd64.tar.gz", "tailcat"},
		{"linux-arm64", "linux", "arm64", "", "tailcat_0.2.0_linux_arm64.tar.gz", "tailcat"},
		{"linux-armv7", "linux", "arm", "7", "tailcat_0.2.0_linux_armv7.tar.gz", "tailcat"},
		{"windows-amd64", "windows", "amd64", "", "tailcat_0.2.0_windows_amd64.zip", "tailcat.exe"},
		{"windows-arm64", "windows", "arm64", "", "tailcat_0.2.0_windows_arm64.zip", "tailcat.exe"},
		{"darwin-amd64", "darwin", "amd64", "", "tailcat_0.2.0_darwin_amd64.tar.gz", "tailcat"},
		{"darwin-arm64", "darwin", "arm64", "", "tailcat_0.2.0_darwin_arm64.tar.gz", "tailcat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var archive []byte
			if tt.goos == "windows" {
				archive = testZIP(t, tt.binaryName, []byte(newBinary))
			} else {
				archive = testTarGz(t, tt.binaryName, []byte(newBinary))
			}
			digest := sha256.Sum256(archive)
			checksums := fmt.Appendf(nil, "%x  %s\n", digest, tt.archiveName)

			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/latest":
					json.NewEncoder(w).Encode(githubRelease{
						TagName: latestVersion,
						Assets: []releaseAsset{
							{Name: tt.archiveName, BrowserDownloadURL: server.URL + "/archive", Size: int64(len(archive))},
							{Name: "checksums.txt", BrowserDownloadURL: server.URL + "/checksums", Size: int64(len(checksums))},
						},
					})
				case "/archive":
					w.Write(archive)
				case "/checksums":
					w.Write(checksums)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			target := filepath.Join(t.TempDir(), tt.binaryName)
			if err := os.WriteFile(target, []byte("old tailcat binary"), 0755); err != nil {
				t.Fatal(err)
			}
			u := &updater{
				client:         server.Client(),
				latestURL:      server.URL + "/latest",
				executablePath: func() (string, error) { return target, nil },
				packageOwner:   func(context.Context, string) string { return "" },
				goos:           tt.goos,
				goarch:         tt.goarch,
				goarm:          tt.goarm,
			}
			result, err := u.run(context.Background(), currentVersion, true)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Updated || result.Current != currentVersion || result.Latest != latestVersion {
				t.Fatalf("result = %+v", result)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != newBinary {
				t.Fatalf("installed binary = %q, want %q", got, newBinary)
			}
			if _, err := os.Stat(updateBackupPath(target)); !os.IsNotExist(err) {
				t.Fatalf("backup still exists: %v", err)
			}
		})
	}
}

func TestLinuxPackageOwnershipChecks(t *testing.T) {
	const exe = "/usr/bin/tailcat"
	checks := linuxPackageOwnershipChecks(exe)
	want := []packageOwnershipCheck{
		{"dpkg-query", []string{"--search", exe}, "dpkg"},
		{"rpm", []string{"-qf", exe}, "RPM"},
		{"pacman", []string{"-Qo", exe}, "pacman"},
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d ownership checks, want %d", len(checks), len(want))
	}
	for i := range want {
		if checks[i].name != want[i].name || checks[i].kind != want[i].kind || !slices.Equal(checks[i].args, want[i].args) {
			t.Errorf("check %d = %+v, want %+v", i, checks[i], want[i])
		}
	}
}

func TestManagedInstallPaths(t *testing.T) {
	for _, tt := range []struct {
		goos, exe, want string
	}{
		{"darwin", "/opt/homebrew/Cellar/tailcat/1.0.0/bin/tailcat", "Homebrew"},
		{"darwin", "/usr/local/Cellar/tailcat/1.0.0/bin/tailcat", "Homebrew"},
		{"linux", "/home/linuxbrew/.linuxbrew/Cellar/tailcat/1.0.0/bin/tailcat", "Homebrew"},
		{"darwin", "/opt/local/bin/tailcat", "MacPorts"},
		{"darwin", "/Users/me/bin/tailcat", ""},
		{"windows", `C:\Users\me\AppData\Local\Microsoft\WinGet\Packages\Tailscale.Tailcat\tailcat.exe`, "WinGet"},
		{"windows", `C:\Program Files\WindowsApps\Tailscale.Tailcat\tailcat.exe`, "Microsoft Store/MSIX"},
		{"windows", `C:\Users\me\scoop\apps\tailcat\current\tailcat.exe`, "Scoop"},
		{"windows", `C:\ProgramData\chocolatey\lib\tailcat\tools\tailcat.exe`, "Chocolatey"},
		{"windows", `C:\Program Files\Tailcat\tailcat.exe`, "the Windows installer"},
		{"windows", `C:\Windows\System32\tailcat.exe`, "Windows"},
		{"windows", `C:\Tools\tailcat.exe`, ""},
	} {
		if got := pathPackageOwner(tt.goos, tt.exe); got != tt.want {
			t.Errorf("pathPackageOwner(%q, %q) = %q, want %q", tt.goos, tt.exe, got, tt.want)
		}
	}
}

func TestWindowsManagedRootOwner(t *testing.T) {
	roots := []windowsManagedRoot{
		{"Scoop", `D:\CustomScoop`, "apps/tailcat"},
		{"Chocolatey", `E:\Packages`, "lib/tailcat"},
	}
	for _, tt := range []struct {
		exe, want string
	}{
		{`D:\CustomScoop\apps\tailcat\current\tailcat.exe`, "Scoop"},
		{`E:\Packages\lib\tailcat\tools\tailcat.exe`, "Chocolatey"},
		{`D:\CustomScoop\apps\other\tailcat.exe`, ""},
	} {
		if got := windowsManagedRootOwner(tt.exe, roots); got != tt.want {
			t.Errorf("windowsManagedRootOwner(%q) = %q, want %q", tt.exe, got, tt.want)
		}
	}
}

func TestWindowsPackageRecordOwner(t *testing.T) {
	for _, tt := range []struct {
		name, exe, want string
		records         []windowsPackageRecord
	}{
		{
			name: "winget portable target in custom root",
			exe:  `D:\PortableApps\Tailcat\tailcat.exe`,
			want: "WinGet",
			records: []windowsPackageRecord{{
				portableTargetFullPath:  `D:\PortableApps\Tailcat\tailcat.exe`,
				winGetPackageIdentifier: "Tailscale.Tailcat",
			}},
		},
		{
			name: "winget custom install directory",
			exe:  `D:\PortableApps\Tailcat\bin\tailcat.exe`,
			want: "WinGet",
			records: []windowsPackageRecord{{
				displayName:             "Tailcat",
				installLocation:         `D:\PortableApps\Tailcat`,
				winGetPackageIdentifier: "Tailscale.Tailcat",
			}},
		},
		{
			name: "registered installer directory",
			exe:  `C:\Users\me\AppData\Local\Programs\Tailcat\tailcat.exe`,
			want: "the Windows installer",
			records: []windowsPackageRecord{{
				displayName:     "Tailcat",
				installLocation: `C:\Users\me\AppData\Local\Programs\Tailcat`,
			}},
		},
		{
			name: "registered display icon",
			exe:  `C:\Apps\Tailcat\tailcat.exe`,
			want: "the Windows installer",
			records: []windowsPackageRecord{{
				displayIcon: `"C:\Apps\Tailcat\tailcat.exe",0`,
			}},
		},
		{
			name: "unrelated broad install directory",
			exe:  `C:\Users\me\bin\tailcat.exe`,
			records: []windowsPackageRecord{{
				displayName:     "Unrelated application",
				installLocation: `C:\Users\me`,
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := windowsPackageRecordOwner(tt.exe, tt.records); got != tt.want {
				t.Fatalf("windowsPackageRecordOwner() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSystemPackageExecutablePath(t *testing.T) {
	for _, tt := range []struct {
		goos, exe string
		want      bool
	}{
		{"linux", "/usr/bin/tailcat", true},
		{"linux", "/usr/sbin/tailcat", true},
		{"linux", "/bin/tailcat", true},
		{"linux", "/sbin/tailcat", true},
		{"linux", "/usr/local/bin/tailcat", false},
		{"linux", "/home/user/bin/tailcat", false},
		{"darwin", "/usr/bin/tailcat", true},
		{"darwin", "/opt/homebrew/bin/tailcat", false},
		{"windows", "/usr/bin/tailcat", false},
	} {
		if got := isSystemPackageExecutablePath(tt.goos, tt.exe); got != tt.want {
			t.Errorf("isSystemPackageExecutablePath(%q, %q) = %v, want %v", tt.goos, tt.exe, got, tt.want)
		}
	}
}

func TestDownloadRejectsInsecureURLAndSizeMismatch(t *testing.T) {
	u := &updater{client: http.DefaultClient}
	if _, err := u.download(context.Background(), releaseAsset{
		Name: "tailcat.zip", BrowserDownloadURL: "http://example.com/tailcat.zip", Size: 1,
	}, 10, "v0.1.0"); err == nil {
		t.Fatal("insecure asset URL unexpectedly succeeded")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("abc"))
	}))
	defer server.Close()
	u.client = server.Client()
	if _, err := u.download(context.Background(), releaseAsset{
		Name: "tailcat.zip", BrowserDownloadURL: server.URL, Size: 4,
	}, 10, "v0.1.0"); err == nil {
		t.Fatal("asset size mismatch unexpectedly succeeded")
	}
}

func TestUpdaterRejectsBadChecksum(t *testing.T) {
	const archiveName = "tailcat_0.2.0_windows_amd64.zip"
	archive := testZIP(t, "tailcat.exe", []byte("new"))
	checksums := []byte(fmt.Sprintf("%064x  %s\n", 1, archiveName))

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			json.NewEncoder(w).Encode(githubRelease{
				TagName: "v0.2.0",
				Assets: []releaseAsset{
					{Name: archiveName, BrowserDownloadURL: server.URL + "/archive", Size: int64(len(archive))},
					{Name: "checksums.txt", BrowserDownloadURL: server.URL + "/checksums", Size: int64(len(checksums))},
				},
			})
			return
		}
		if r.URL.Path == "/archive" {
			w.Write(archive)
			return
		}
		w.Write(checksums)
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "tailcat.exe")
	if err := os.WriteFile(target, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	u := &updater{
		client:         server.Client(),
		latestURL:      server.URL + "/latest",
		executablePath: func() (string, error) { return target, nil },
		packageOwner:   func(context.Context, string) string { return "" },
		goos:           "windows",
		goarch:         "amd64",
	}
	if _, err := u.run(context.Background(), "v0.1.0", true); err == nil {
		t.Fatal("bad checksum unexpectedly succeeded")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("target changed after rejected update: %q", got)
	}
}

func testZIP(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testTarGz(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
