# tailcat changelog

## Unreleased

- `exec` service: `tailcat serve exec -- <command>` runs the command
  for each incoming connection with the connection as its stdin and
  stdout, like inetd. With the `ssh` or `no-auth-ssh` service, the
  command after `--` instead replaces the shell for every session,
  like OpenSSH's `ForceCommand`, with no shell, client-chosen command,
  or SFTP offered.

## v0.6.0 (2026-09-04)

- Application-layer UDP support: servers can serve and forward UDP
  flows, clients can dial UDP ports, and `tailcat socks` supports
  SOCKS5 UDP ASSOCIATE. Idle incoming UDP flows close after a
  configurable timeout, two minutes by default. ([#25](https://github.com/tailscale/tailcat/pull/25), [@sksingh2005](https://github.com/sksingh2005))
- SSH public key authentication: `tailcat serve ssh` takes
  `--ssh-authorized-keys` with literal keys, key files, or
  `user@github` to fetch a GitHub user's keys. ([#88](https://github.com/tailscale/tailcat/pull/88))
- tailcat addresses now include a WireGuard pre-shared key by default;
  `--psk=false` opts out, and servers warn when serving without one. ([#85](https://github.com/tailscale/tailcat/pull/85))
- `tailcat forward` can forward through exit-node servers to arbitrary
  IP:port targets, and a local port of 0 picks a free one. ([#75](https://github.com/tailscale/tailcat/pull/75), [@Audi-dask](https://github.com/Audi-dask))
- `--derpmap-url` defaults from the `TAILCAT_DERPMAP_URL` environment
  variable. ([#72](https://github.com/tailscale/tailcat/pull/72))
- Served processes receive the authenticated peer's node key in
  `TAILCAT_PEER_KEY`, in the same `nodekey:...` form `--allow` takes.
  ([#89](https://github.com/tailscale/tailcat/pull/89), [@seffs](https://github.com/seffs))
- `tailcat genkey --embed-derp-map` no longer panics when no fixed
  region is set, and unknown `--region` values report an error naming
  the missing region. ([#91](https://github.com/tailscale/tailcat/pull/91), [@gmkbenjamin](https://github.com/gmkbenjamin); reported by [@chanchiwai-ray](https://github.com/chanchiwai-ray))
- Proxied TCP connections finish their teardown instead of losing data
  queued at close. ([#83](https://github.com/tailscale/tailcat/pull/83))
- Connection setup resends pings lost by busy relays instead of
  waiting out whole timeouts, and SOCKS dials get a longer budget than
  a single WireGuard handshake. ([#71](https://github.com/tailscale/tailcat/pull/71))
- Packaging: the Nix flake builds in CI with Go built from source and
  an automatically refreshed vendor hash; conda-forge installation is
  documented ([#76](https://github.com/tailscale/tailcat/pull/76), [@pavelzw](https://github.com/pavelzw)); the test suite is hermetic and several times
  faster, for reliable distro package builds.

## v0.5.0 (2026-09-02)

- New `tailcat forward` subcommand: listen on a local TCP port and
  forward each connection to a tailcat server. ([#62](https://github.com/tailscale/tailcat/pull/62), [@Audi-dask](https://github.com/Audi-dask))
- The connection string is now called a "tailcat address" everywhere;
  the old flag spellings remain as hidden aliases.
- Write-only file shares are actually write-only: drop boxes no longer
  leak whether a file already exists, and the new `:wo+` mode allows
  overwrites.
- Mistyped addresses no longer fall through to DNS lookups.
- Hardened validation of arguments passed to ssh and scp child
  processes.
- Added SECURITY.md.
- Windows: the SSH server looks for pwsh.exe. ([#61](https://github.com/tailscale/tailcat/pull/61), [@gcurtis](https://github.com/gcurtis))

## v0.4.0 (2026-08-31)

- File transfer: servers share a directory with
  `tailcat serve --files=DIR` (read-only, read-write, or write-only
  drop box modes) over the SSH SFTP subsystem, and new `cp`, `recv`,
  and `ls` subcommands use it. ([#48](https://github.com/tailscale/tailcat/pull/48))
- New `serve` subcommand as the long-form way to run servers.
- The CLI was rewritten with declarative subcommands: fuller help with
  examples on every subcommand, and requested help prints to stdout.
- SSH support on Windows, and CI now tests macOS and Windows; the
  integration tests were made Windows-portable. ([#34](https://github.com/tailscale/tailcat/pull/34), [@FenjuFu](https://github.com/FenjuFu))
- Official release binaries build with a trimmed feature set for
  smaller size; the tag list is documented in build-tags.md.
- Addresses with null DERP regions or nodes are rejected, and the meow
  packet encoding gained tests. ([#52](https://github.com/tailscale/tailcat/pull/52), [#44](https://github.com/tailscale/tailcat/pull/44), [@CharmingGroot](https://github.com/CharmingGroot))
- `genkey --client --key=default` is rejected as a likely mix-up, and
  `--version` keeps working as an unadvertised alias.
- The Nix flake's vendor hash stays fresh automatically.
- Documented Homebrew installation for macOS.

## v0.3.0 (2026-08-30)

- Node and disco keys are now separate, matching Tailscale's split
  between identity and path discovery.
- Local dev DERP mode is usable end to end and tested hermetically.
- Clients drain the final ACK before exiting, so the last bytes of a
  transfer are not lost at close.
- Documented the Arch Linux package. ([#30](https://github.com/tailscale/tailcat/pull/30), [@BarbUk](https://github.com/BarbUk))

## v0.2.0 (2026-08-30)

- Addresses with malformed public keys are rejected with a clear
  error instead of failing later. ([#26](https://github.com/tailscale/tailcat/pull/26), [@keyurbodar](https://github.com/keyurbodar))
- Fixed a close panic in the browser (Wasm) build.
- Documented the prebuilt binaries and container image.

## v0.1.0 (2026-08-30)

First tagged release. Highlights:

- Release process: static Linux binaries, deb and rpm packages,
  Windows zips, checksums, and container images on ghcr.io.
- Browser demo published to GitHub Pages, with the demo reusable by
  other servers.
- A Nix flake.
- DERP maps are cached on disk with ETag revalidation, plus a
  process-wide in-memory cache.
- `ping` reports the network path and gained `--until-direct`; peers
  advertise their endpoints on important events so direct paths form
  reliably.
- `genkey --fixed-region` bakes a region choice into a key.
- The Go library's zero value `Server` and `Client` are usable
  directly.
- Closing a `Server` closes its active connections and backend
  resources. ([#19](https://github.com/tailscale/tailcat/pull/19), [@0xcadams](https://github.com/0xcadams))
- SOCKS mode runs without a child command, takes a custom listen
  address ([#20](https://github.com/tailscale/tailcat/pull/20), [@tw4452852](https://github.com/tw4452852)), and uses the configured client key.
- The ssh ProxyCommand forwards a custom DERP map ([#22](https://github.com/tailscale/tailcat/pull/22), [@zukka77](https://github.com/zukka77)) and uses
  a short deterministic ControlPath ([#15](https://github.com/tailscale/tailcat/pull/15), [@korjavin](https://github.com/korjavin)).
- README fixes. ([#21](https://github.com/tailscale/tailcat/pull/21), [@CooperSheroy](https://github.com/CooperSheroy))

## derpcat becomes its own Go module (2026-03-07)

- Left the tailscale.com fork: commit
  [68ac83e73](https://github.com/tailscale/tailcat/commit/68ac83e73)
  ("derpcat: use tailscale.com as a library instead of forking") made
  derpcat its own Go module, depending on tailscale.com as a regular
  library. Renamed to tailcat in
  [e6b242f14](https://github.com/tailscale/tailcat/commit/e6b242f14)
  (2026-07-17). ([@bradfitz](https://github.com/bradfitz))

## derpcat (2023-09-14)

- First worked, as "derpcat" inside a fork of the tailscale.com repo,
  in commit
  [911915fbb](https://github.com/tailscale/tailcat/commit/911915fbb)
  ("derpcat: it's alive!"), written on UA 605 PDX-ORD without buying
  the wifi. ([@bradfitz](https://github.com/bradfitz))
