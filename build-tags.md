# build-tags.txt

The [build-tags.txt](./build-tags.txt) file next to this one is the
list of Go build tags that official tailcat binaries are built with.

## Why it exists

tailcat uses [tailscale.com](https://pkg.go.dev/tailscale.com) as a
library but only needs its data plane. Upstream maintains a registry
of omittable features (`tailscale.com/feature/featuretags`), each
disabled by a `ts_omit_<feature>` build tag. Building with the tags in
build-tags.txt omits every feature tailcat doesn't use, which makes
the binaries about 16% smaller.

## For packagers

If you package tailcat from source (Homebrew, AUR, NixOS, etc.),
build the same way the official releases are built:

```sh
go build -tags "$(cat build-tags.txt)" -ldflags "-s -w" ./cmd/tailcat
```

The file is a single comma-separated line, usable directly as the
argument to the --tags flag as above. Building without the tags is
also fine and loses nothing but size.

## Where the list lives and how the copies stay in sync

The source of truth is `ReleaseTags` in
[internal/buildtags](./internal/buildtags/buildtags.go), which
computes the list from the upstream featuretags registry: a small
allowlist of features tailcat needs is expanded with its dependencies,
and everything else in the registry gets its `ts_omit_` tag.

Because not every consumer can run Go code, the computed list is
copied into two places:

* **build-tags.txt**: the file described above, for packagers and for
  the CI job that cross-builds every release target
  ([.github/workflows/test.yml](./.github/workflows/test.yml)).
* **.goreleaser.yaml**: a `-tags=` line in the `flags` of the release
  build, since GoReleaser cannot read the list from a file.

A test, [internal/buildtags/sync_test.go](./internal/buildtags/sync_test.go),
fails if either copy differs from `ReleaseTags`, so the copies cannot
silently drift from the source of truth or from each other. When the
list changes (a new keep-list entry here, or new features in the
upstream registry after a tailscale.com bump), regenerate both copies
from the output of:

```sh
go run ./internal/buildtags/printtags
```

Two more consumers use `ReleaseTags` directly and need no
regeneration: the cmd/tailcat integration tests build the binary they
test with it, so CI exercises exactly what releases ship, and the
`release-tags` CI job cross-builds all release platforms with
build-tags.txt.

The js/wasm web build has its own shorter allowlist (`WasmTags` in the
same package), computed at build time by cmd/tailcat-web and friends
rather than checked in.
