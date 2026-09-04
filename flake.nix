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
        # go.mod requires Go 1.27.1 (via tailscale.com), but as of
        # 2026-09 nixpkgs-unstable ships go_1_27 = 1.27.0, so build
        # 1.27.1 from source. Remove this override and go back to
        # plain pkgs.go_1_27 once the nixpkgs bump
        # (NixOS/nixpkgs#559618) reaches nixpkgs-unstable.
        go = pkgs.go_1_27.overrideAttrs (old: {
          version = "1.27.1";
          src = pkgs.fetchurl {
            url = "https://go.dev/dl/go1.27.1.src.tar.gz";
            hash = "sha256-TkCKuuEm2Ra2FkYnGT8sVPDjyhMS1pO4bbRfhiqyOLE=";
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
# nix-direnv cache busting line: sha256-hpFVgsUKswE7g69EieoeKGPR1nVkcRmBhDKbnB2CDBg=
