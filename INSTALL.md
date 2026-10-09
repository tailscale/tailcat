# Installing tailcat

This page lists the ways to install the `tailcat` CLI. For what
tailcat is and how to use it, see the [README](./README.md).

## Prebuilt binaries

Prebuilt binaries are on the
[Releases page](https://github.com/tailscale/tailcat/releases): static
Linux binaries (tar.gz) plus Debian (.deb) and RPM (.rpm) packages for
amd64, arm64, and armv7, and Windows binaries (zip) for amd64 and
arm64.

## Homebrew (macOS)

For macOS, install with [Homebrew](https://brew.sh/):

```sh
$ brew install tailcat
```

## Scoop (Windows)

For Windows, install with [Scoop](https://scoop.sh/). The package is
in Scoop's main bucket, so no extra bucket is needed:

```sh
$ scoop install tailcat
```

## Snap (Linux)

[![tailcat on the Snap Store](https://snapcraft.io/tailcat/badge.svg)](https://snapcraft.io/tailcat)

For Linux distros with [snapd](https://snapcraft.io/docs/installing-snapd),
install from the [Snap Store](https://snapcraft.io/tailcat):

```sh
$ sudo snap install tailcat
```

The snap is community-maintained (packaging source at
[chanchiwai-ray/tailcat-snap](https://github.com/chanchiwai-ray/tailcat-snap))
and built from the upstream release tag with the recommended build
tags. It's strictly confined: it can read and write files under your
home directory but not elsewhere, and it bundles its own OpenSSH
client for `tailcat ssh` and `tailcat cp`. As with any snap, its
config (including the tailcat key and ssh's `.ssh` directory) lives
under the snap's private home, `~/snap/tailcat/current`, rather than
your real `~/.config` and `~/.ssh`.

## Container image

There's a
[container image](https://github.com/tailscale/tailcat/pkgs/container/tailcat):

```sh
$ docker pull ghcr.io/tailscale/tailcat:latest  # or :vx.y.z
$ docker run --rm -i ghcr.io/tailscale/tailcat:latest
```

Don't add `-t`: a pty is a single byte stream, so it merges the
status output that tailcat writes to stderr (including the listening
address) into stdout with the tunnel data, and no redirection can
separate the two again. Use `-i` alone when piping through stdin.

## Go toolchain

Build from source with a Go toolchain:

```sh
$ go install github.com/tailscale/tailcat/cmd/tailcat@latest
```

This works on any operating system Go supports. It's the only install
method for FreeBSD and OpenBSD, which are expected to work but aren't
regularly tested; CI checks that they keep compiling. It's also the
only way to target browsers: the tailcat Go library and the web demo
(the `web` directory in this repo) build for js/wasm.

## Nix

With Nix, from [nixpkgs](https://search.nixos.org/packages?channel=unstable&query=tailcat):

```sh
$ nix profile install nixpkgs#tailcat
$ nix-env -iA nixpkgs.tailcat  # or with classic nix-env
```

Or with Nix flakes from this repo, run it directly or install it:

```sh
$ nix run github:tailscale/tailcat
$ nix profile install github:tailscale/tailcat
```

## Arch Linux (AUR)

[![tailcat on AUR](https://img.shields.io/aur/version/tailcat?label=tailcat)](https://aur.archlinux.org/packages/tailcat/)
[![tailcat-bin on AUR](https://img.shields.io/aur/version/tailcat-bin?label=tailcat-bin)](https://aur.archlinux.org/packages/tailcat-bin/)

```bash
# Build release package from source
yay -S tailcat

# OR install the binary release
yay -S tailcat-bin
```

## conda-forge

[![tailcat on conda-forge](https://img.shields.io/conda/vn/conda-forge/tailcat?logo=conda-forge)](https://prefix.dev/channels/conda-forge/packages/tailcat)
[![tailcat on conda-forge](https://img.shields.io/conda/pn/conda-forge/tailcat?logo=conda-forge)](https://prefix.dev/channels/conda-forge/packages/tailcat)

```bash
pixi global install tailcat
# run without installation
pixi exec tailcat
```

## Packaging from source

The official binaries are built with a list of build tags that omits
unused Tailscale features, making them about 16% smaller. The
recommended tag list is checked in as
[build-tags.txt](./build-tags.txt) (and kept accurate by a CI test),
so packagers (Homebrew, AUR, NixOS, etc.) can build the same way:

```sh
$ go build -tags "$(cat build-tags.txt)" -ldflags "-s -w" ./cmd/tailcat
```

See [build-tags.md](./build-tags.md) for the details.
