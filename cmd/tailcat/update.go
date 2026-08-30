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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	latestReleaseURL   = "https://api.github.com/repos/tailscale/tailcat/releases/latest"
	updateTimeout      = 2 * time.Minute
	maxReleaseResponse = 1 << 20   // 1 MiB
	maxChecksums       = 1 << 20   // 1 MiB
	maxReleaseAsset    = 128 << 20 // 128 MiB
	maxBinary          = 128 << 20 // 128 MiB
	maxExpandedArchive = 256 << 20 // 256 MiB
	maxArchiveEntries  = 1024
)

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
}

type githubRelease struct {
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []releaseAsset `json:"assets"`
}

type updateResult struct {
	Current string
	Latest  string
	Updated bool
}

type updater struct {
	client         *http.Client
	latestURL      string
	now            func() time.Time
	lockPath       func() (string, error)
	executablePath func() (string, error)
	packageOwner   func(context.Context, string) string
	goos           string
	goarch         string
	goarm          string
}

func newUpdater() *updater {
	return &updater{
		client:         newUpdateHTTPClient(),
		latestURL:      latestReleaseURL,
		now:            time.Now,
		lockPath:       defaultUpdateLockPath,
		executablePath: resolvedExecutablePath,
		packageOwner:   installedPackageOwner,
		goos:           runtime.GOOS,
		goarch:         runtime.GOARCH,
		goarm:          currentGOARM(),
	}
}

func newUpdateHTTPClient() *http.Client {
	return &http.Client{
		Timeout: updateTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing update download redirect from HTTPS to an insecure URL")
			}
			if len(via) >= 10 {
				return errors.New("too many update download redirects")
			}
			return nil
		},
	}
}

func defaultUpdateLockPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tailcat", "update.lock"), nil
}

func resolvedExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find running executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve running executable: %w", err)
	}
	return filepath.Clean(exe), nil
}

func currentGOARM() string {
	if runtime.GOARCH != "arm" {
		return ""
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range bi.Settings {
			if setting.Key == "GOARM" {
				return setting.Value
			}
		}
	}
	return os.Getenv("GOARM")
}

func updateMode() {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "check for an update without installing it")
	fs.Parse(flag.Args()[1:]) // stripping off "update"
	if len(fs.Args()) != 0 {
		usage("tailcat update takes no positional arguments")
	}

	u := newUpdater()
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	var result updateResult
	var err error
	if *check {
		result, err = u.run(ctx, versionString(), false)
	} else {
		result, err = u.runWithLock(ctx, versionString())
	}
	if err != nil {
		fatalUpdate(err)
	}
	printUpdateResult(result, *check)
}

func fatalUpdate(err error) {
	fmt.Fprintf(os.Stderr, "tailcat update: %v\n", err)
	os.Exit(1)
}

func (u *updater) runWithLock(ctx context.Context, current string) (updateResult, error) {
	releaseLock, acquired, err := u.acquireLock()
	if err != nil {
		return updateResult{}, err
	}
	if !acquired {
		return updateResult{}, errors.New("another tailcat update is already in progress")
	}
	defer releaseLock()
	return u.run(ctx, current, true)
}

func printUpdateResult(result updateResult, checkOnly bool) {
	switch {
	case result.Updated:
		fmt.Printf("updated tailcat from %s to %s; the new version will run on the next launch\n", result.Current, result.Latest)
	case result.Current == result.Latest:
		fmt.Printf("tailcat %s is up to date\n", result.Current)
	case compareReleaseVersions(result.Current, result.Latest) > 0:
		fmt.Printf("tailcat %s is newer than the latest release %s\n", result.Current, result.Latest)
	case checkOnly:
		fmt.Printf("tailcat %s is installed; %s is available\n", result.Current, result.Latest)
	default:
		fmt.Printf("tailcat %s was not updated\n", result.Current)
	}
}

func (u *updater) run(ctx context.Context, current string, apply bool) (updateResult, error) {
	if _, err := parseReleaseVersion(current); err != nil {
		return updateResult{}, fmt.Errorf("cannot update development build with version %q", current)
	}
	rel, err := u.latestRelease(ctx, current)
	if err != nil {
		return updateResult{}, err
	}
	if _, err := parseReleaseVersion(rel.TagName); err != nil {
		return updateResult{}, fmt.Errorf("latest release has invalid version %q", rel.TagName)
	}
	result := updateResult{Current: current, Latest: rel.TagName}
	if compareReleaseVersions(current, rel.TagName) >= 0 {
		return result, nil
	}

	archiveAsset, err := releaseArchiveAsset(rel, u.goos, u.goarch, u.goarm)
	if err != nil {
		return updateResult{}, err
	}
	if !apply {
		return result, nil
	}

	exe, err := u.executablePath()
	if err != nil {
		return updateResult{}, err
	}
	if err := u.checkInstallMethod(ctx, exe); err != nil {
		return updateResult{}, err
	}
	archiveName := archiveAsset.Name
	checksumsAsset, err := uniqueReleaseAsset(rel.Assets, "checksums.txt")
	if err != nil {
		return updateResult{}, fmt.Errorf("release %s: %w", rel.TagName, err)
	}

	checksums, err := u.download(ctx, checksumsAsset, maxChecksums, current)
	if err != nil {
		return updateResult{}, fmt.Errorf("download checksums: %w", err)
	}
	wantHash, err := checksumForAsset(checksums, archiveName)
	if err != nil {
		return updateResult{}, err
	}
	archiveBytes, err := u.download(ctx, archiveAsset, maxReleaseAsset, current)
	if err != nil {
		return updateResult{}, fmt.Errorf("download %s: %w", archiveName, err)
	}
	gotHash := sha256.Sum256(archiveBytes)
	if !bytes.Equal(gotHash[:], wantHash) {
		return updateResult{}, fmt.Errorf("SHA-256 mismatch for %s: got %x, want %x", archiveName, gotHash, wantHash)
	}
	binary, err := extractReleaseBinary(archiveName, archiveBytes, u.goos)
	if err != nil {
		return updateResult{}, err
	}
	if err := replaceExecutable(exe, binary); err != nil {
		return updateResult{}, err
	}
	result.Updated = true
	return result, nil
}

func (u *updater) latestRelease(ctx context.Context, current string) (githubRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.latestURL, nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "tailcat/"+current)
	resp, err := u.client.Do(req)
	if err != nil {
		return githubRelease{}, fmt.Errorf("query latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("query latest release: HTTP %s", resp.Status)
	}
	body, err := readAtMost(resp.Body, maxReleaseResponse)
	if err != nil {
		return githubRelease{}, fmt.Errorf("read latest release: %w", err)
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return githubRelease{}, fmt.Errorf("decode latest release: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return githubRelease{}, fmt.Errorf("GitHub latest release %q is not a stable published release", rel.TagName)
	}
	return rel, nil
}

func (u *updater) download(ctx context.Context, asset releaseAsset, maxSize int64, current string) ([]byte, error) {
	if asset.BrowserDownloadURL == "" {
		return nil, fmt.Errorf("asset %q has no download URL", asset.Name)
	}
	assetURL, err := url.Parse(asset.BrowserDownloadURL)
	if err != nil || assetURL.Scheme != "https" || assetURL.Host == "" {
		return nil, fmt.Errorf("asset %q has invalid HTTPS download URL", asset.Name)
	}
	if asset.Size <= 0 || asset.Size > maxSize {
		return nil, fmt.Errorf("asset %q has invalid size %d", asset.Name, asset.Size)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "tailcat/"+current)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	b, err := readAtMost(resp.Body, maxSize)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != asset.Size {
		return nil, fmt.Errorf("asset %q size mismatch: got %d, want %d", asset.Name, len(b), asset.Size)
	}
	if err := verifyAssetDigest(asset, b); err != nil {
		return nil, err
	}
	return b, nil
}

func verifyAssetDigest(asset releaseAsset, b []byte) error {
	if asset.Digest == "" {
		return nil
	}
	algorithm, encoded, ok := strings.Cut(asset.Digest, ":")
	if !ok || algorithm != "sha256" {
		return fmt.Errorf("asset %q uses unsupported digest %q", asset.Name, asset.Digest)
	}
	want, err := hex.DecodeString(encoded)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("asset %q has invalid digest %q", asset.Name, asset.Digest)
	}
	got := sha256.Sum256(b)
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("GitHub digest mismatch for %s: got %x, want %x", asset.Name, got, want)
	}
	return nil
}

func readAtMost(r io.Reader, maxSize int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxSize {
		return nil, fmt.Errorf("response exceeds %d bytes", maxSize)
	}
	return b, nil
}

func uniqueReleaseAsset(assets []releaseAsset, name string) (releaseAsset, error) {
	var found *releaseAsset
	for _, asset := range assets {
		if asset.Name == name {
			if found != nil {
				return releaseAsset{}, fmt.Errorf("contains duplicate asset %q", name)
			}
			assetCopy := asset
			found = &assetCopy
		}
	}
	if found == nil {
		return releaseAsset{}, fmt.Errorf("has no asset %q", name)
	}
	return *found, nil
}

// releaseArchiveAsset follows the archives.name_template in .goreleaser.yaml.
// It intentionally discovers the current GOOS/GOARCH in the release assets
// rather than keeping a second platform allowlist that can drift from the
// release matrix.
func releaseArchiveAsset(rel githubRelease, goos, goarch, goarm string) (releaseAsset, error) {
	base, err := releaseArchiveBase(rel.TagName, goos, goarch, goarm)
	if err != nil {
		return releaseAsset{}, err
	}
	validNames := map[string]bool{
		base + ".tar.gz": true,
		base + ".zip":    true,
	}
	var found *releaseAsset
	for _, asset := range rel.Assets {
		if !validNames[asset.Name] {
			continue
		}
		if found != nil {
			return releaseAsset{}, fmt.Errorf("release %s has multiple prebuilt archives for %s/%s", rel.TagName, goos, goarch)
		}
		assetCopy := asset
		found = &assetCopy
	}
	if found == nil {
		return releaseAsset{}, fmt.Errorf("release %s has no prebuilt archive for %s/%s", rel.TagName, goos, goarch)
	}
	return *found, nil
}

func releaseArchiveBase(version, goos, goarch, goarm string) (string, error) {
	parsed, err := parseReleaseVersion(version)
	if err != nil {
		return "", err
	}
	if !validReleaseComponent(goos) || !validReleaseComponent(goarch) {
		return "", fmt.Errorf("invalid release platform %q/%q", goos, goarch)
	}
	suffix := ""
	if goarch == "arm" {
		goarm, _, _ = strings.Cut(goarm, ",")
		if goarm == "" || !validReleaseComponent(goarm) {
			return "", fmt.Errorf("cannot determine the GOARM release variant")
		}
		suffix = "v" + goarm
	}
	return fmt.Sprintf("tailcat_%d.%d.%d_%s_%s%s", parsed[0], parsed[1], parsed[2], goos, goarch, suffix), nil
}

func validReleaseComponent(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func parseReleaseVersion(v string) ([3]int, error) {
	var ret [3]int
	if !strings.HasPrefix(v, "v") {
		return ret, fmt.Errorf("invalid release version %q", v)
	}
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return ret, fmt.Errorf("invalid release version %q", v)
	}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return ret, fmt.Errorf("invalid release version %q", v)
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return ret, fmt.Errorf("invalid release version %q", v)
			}
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return ret, fmt.Errorf("invalid release version %q", v)
		}
		ret[i] = n
	}
	return ret, nil
}

func compareReleaseVersions(a, b string) int {
	av, aErr := parseReleaseVersion(a)
	bv, bErr := parseReleaseVersion(b)
	if aErr != nil || bErr != nil {
		return strings.Compare(a, b)
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

func checksumForAsset(checksums []byte, assetName string) ([]byte, error) {
	var found []byte
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != assetName {
			continue
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 for %s in checksums.txt", assetName)
		}
		if found != nil {
			return nil, fmt.Errorf("checksums.txt has duplicate entries for %s", assetName)
		}
		found = digest
	}
	if found == nil {
		return nil, fmt.Errorf("checksums.txt has no SHA-256 for %s", assetName)
	}
	return found, nil
}

func extractReleaseBinary(archiveName string, archive []byte, goos string) ([]byte, error) {
	binaryName := "tailcat"
	if goos == "windows" {
		binaryName += ".exe"
	}
	if strings.HasSuffix(archiveName, ".zip") {
		return extractZIPBinary(archiveName, archive, binaryName)
	}
	if strings.HasSuffix(archiveName, ".tar.gz") {
		return extractTarGzBinary(archiveName, archive, binaryName)
	}
	return nil, fmt.Errorf("unsupported release archive %q", archiveName)
}

func extractZIPBinary(archiveName string, archive []byte, binaryName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", archiveName, err)
	}
	var found []byte
	var expanded uint64
	if len(zr.File) > maxArchiveEntries {
		return nil, fmt.Errorf("%s contains too many entries", archiveName)
	}
	for _, f := range zr.File {
		if f.UncompressedSize64 > uint64(maxExpandedArchive)-expanded {
			return nil, fmt.Errorf("expanded %s exceeds %d bytes", archiveName, maxExpandedArchive)
		}
		expanded += f.UncompressedSize64
		if path.Clean(f.Name) != binaryName {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%s contains duplicate %s entries", archiveName, binaryName)
		}
		if !f.Mode().IsRegular() || f.UncompressedSize64 > maxBinary {
			return nil, fmt.Errorf("invalid %s entry in %s", binaryName, archiveName)
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		found, err = readAtMost(r, maxBinary)
		closeErr := r.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%s contains no %s", archiveName, binaryName)
	}
	return found, nil
}

func extractTarGzBinary(archiveName string, archive []byte, binaryName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", archiveName, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found []byte
	var expanded int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", archiveName, err)
		}
		entries++
		if entries > maxArchiveEntries {
			return nil, fmt.Errorf("%s contains too many entries", archiveName)
		}
		if hdr.Size < 0 || hdr.Size > maxExpandedArchive-expanded {
			return nil, fmt.Errorf("expanded %s exceeds %d bytes", archiveName, maxExpandedArchive)
		}
		expanded += hdr.Size
		if path.Clean(hdr.Name) != binaryName {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%s contains duplicate %s entries", archiveName, binaryName)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size < 0 || hdr.Size > maxBinary {
			return nil, fmt.Errorf("invalid %s entry in %s", binaryName, archiveName)
		}
		found, err = readAtMost(tr, maxBinary)
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%s contains no %s", archiveName, binaryName)
	}
	return found, nil
}

func replaceExecutable(exe string, binary []byte) error {
	fi, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("stat current executable: %w", err)
	}
	dir := filepath.Dir(exe)
	staged, err := os.CreateTemp(dir, ".tailcat-update-*")
	if err != nil {
		return fmt.Errorf("create update beside %s: %w", exe, err)
	}
	stagedName := staged.Name()
	defer func() {
		staged.Close()
		os.Remove(stagedName)
	}()
	if _, err := staged.Write(binary); err != nil {
		return fmt.Errorf("write staged update: %w", err)
	}
	if err := staged.Chmod(fi.Mode().Perm()); err != nil {
		return fmt.Errorf("set staged update permissions: %w", err)
	}
	if err := staged.Sync(); err != nil {
		return fmt.Errorf("sync staged update: %w", err)
	}
	if err := staged.Close(); err != nil {
		return fmt.Errorf("close staged update: %w", err)
	}

	return installStagedExecutable(stagedName, exe)
}

func updateBackupPath(exe string) string {
	return exe + ".tailcat-update-old"
}

func (u *updater) acquireLock() (release func(), acquired bool, err error) {
	lockPath, err := u.lockPath()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return nil, false, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
				f.Close()
				os.Remove(lockPath)
				return nil, false, err
			}
			if err := f.Close(); err != nil {
				os.Remove(lockPath)
				return nil, false, err
			}
			return func() { os.Remove(lockPath) }, true, nil
		}
		if !os.IsExist(err) {
			return nil, false, err
		}
		fi, statErr := os.Stat(lockPath)
		if statErr != nil || u.now().Sub(fi.ModTime()) <= 10*time.Minute {
			return func() {}, false, nil
		}
		if err := os.Remove(lockPath); err != nil {
			return nil, false, err
		}
	}
	return func() {}, false, nil
}

func (u *updater) checkInstallMethod(ctx context.Context, exe string) error {
	clean := filepath.ToSlash(exe)
	if strings.HasPrefix(clean, "/nix/store/") {
		return errors.New("this executable is managed by Nix; update it with nix profile upgrade")
	}
	if owner := u.packageOwner(ctx, exe); owner != "" {
		return fmt.Errorf("this executable is managed by %s; update it with that package manager", owner)
	}
	if owner := pathPackageOwner(u.goos, exe); owner != "" {
		return fmt.Errorf("this executable is managed by %s; update it with that package manager", owner)
	}
	if isSystemPackageExecutablePath(u.goos, exe) {
		return errors.New("this executable is in a system package directory; update it with the package manager or install a standalone binary elsewhere")
	}
	probe, err := os.CreateTemp(filepath.Dir(exe), ".tailcat-update-permission-*")
	if err != nil {
		return fmt.Errorf("the executable directory is not writable: %w", err)
	}
	probeName := probe.Name()
	if err := probe.Close(); err != nil {
		os.Remove(probeName)
		return fmt.Errorf("close update permission probe: %w", err)
	}
	if err := os.Remove(probeName); err != nil {
		return fmt.Errorf("remove update permission probe: %w", err)
	}
	return nil
}

func pathPackageOwner(goos, exe string) string {
	clean := path.Clean(filepath.ToSlash(exe))
	if (goos == "darwin" || goos == "linux") &&
		(strings.Contains(clean, "/Cellar/tailcat/") || strings.Contains(clean, "/Caskroom/tailcat/")) {
		return "Homebrew"
	}
	if goos == "darwin" && (clean == "/opt/local" || strings.HasPrefix(clean, "/opt/local/")) {
		return "MacPorts"
	}
	if goos == "windows" {
		clean = normalizeWindowsPath(exe)
		switch {
		case strings.Contains(clean, "/microsoft/winget/packages/"), strings.Contains(clean, "/winget/packages/"),
			strings.Contains(clean, "/microsoft/winget/links/"), strings.Contains(clean, "/winget/links/"):
			return "WinGet"
		case strings.Contains(clean, "/windowsapps/"):
			return "Microsoft Store/MSIX"
		case strings.Contains(clean, "/scoop/apps/tailcat/"):
			return "Scoop"
		case strings.Contains(clean, "/chocolatey/lib/tailcat/"):
			return "Chocolatey"
		case strings.Contains(clean, "/program files/"), strings.Contains(clean, "/program files (x86)/"):
			return "the Windows installer"
		case strings.Contains(clean, ":/windows/"):
			return "Windows"
		}
	}
	return ""
}

func isSystemPackageExecutablePath(goos, exe string) bool {
	if goos != "linux" && goos != "darwin" {
		return false
	}
	switch path.Dir(path.Clean(filepath.ToSlash(exe))) {
	case "/usr/bin", "/usr/sbin", "/bin", "/sbin":
		return true
	default:
		return false
	}
}

func installedPackageOwner(ctx context.Context, exe string) string {
	if runtime.GOOS == "windows" {
		return windowsPackageOwner(exe)
	}
	if runtime.GOOS != "linux" {
		return ""
	}
	for _, check := range linuxPackageOwnershipChecks(exe) {
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := exec.CommandContext(checkCtx, check.name, check.args...).Run()
		cancel()
		if err == nil {
			return check.kind
		}
	}
	return ""
}

type packageOwnershipCheck struct {
	name string
	args []string
	kind string
}

func linuxPackageOwnershipChecks(exe string) []packageOwnershipCheck {
	return []packageOwnershipCheck{
		{"dpkg-query", []string{"--search", exe}, "dpkg"},
		{"rpm", []string{"-qf", exe}, "RPM"},
		{"pacman", []string{"-Qo", exe}, "pacman"},
	}
}
