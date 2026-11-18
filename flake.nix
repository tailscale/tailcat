{
  description = "tailcat: netcat over Tailscale's data plane, without its control plane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # flakehashes.json is maintained by `make tidy`
        # (tool/updateflakes); do not edit it by hand.
        flakeHashes = builtins.fromJSON (builtins.readFile ./flakehashes.json);
        # go.mod requires Go 1.27.4 (via tailscale.com), but as of
        # 2026-11-17 nixpkgs-unstable ships go_1_27 = 1.27.3, so build
        # 1.27.4 from source. Remove this override and go back to
        # pkgs.buildGo127Module and pkgs.go_1_27 once nixpkgs-unstable
        # has 1.27.4.
        go = pkgs.go_1_27.overrideAttrs (old: {
          version = "1.27.4";
          src = pkgs.fetchurl {
            url = "https://go.dev/dl/go1.27.4.src.tar.gz";
            hash = "sha256-c8+4VxrsDAEXdofbhxY9Rqog6XeWcncokaoXZU2aYJk=";
          };
        });
        buildGoModule = pkgs.buildGoModule.override { inherit go; };
      in
      {
        packages.default = buildGoModule {
          pname = "tailcat";
          version = self.shortRev or "dev";
          src = self;
          subPackages = [ "cmd/tailcat" ];
          vendorHash = flakeHashes.vendor.sri;
          meta = {
            description = "netcat over Tailscale's data plane, without its control plane";
            homepage = "https://github.com/tailscale/tailcat";
            license = pkgs.lib.licenses.bsd3;
            mainProgram = "tailcat";
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [ go ];
        };
      });
}
# nix-direnv cache busting line: sha256-5fgAH39U6wp2SYhBm/OMMr8hDOO3gSRacXYL3aMx77E=
