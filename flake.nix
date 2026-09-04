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
        # go.mod requires Go 1.27, which is newer than the default
        # pkgs.go/buildGoModule as of 2026-08.
        buildGoModule = pkgs.buildGoModule.override { go = pkgs.go_1_27; };
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
          packages = [ pkgs.go_1_27 ];
        };
      });
}
# nix-direnv cache busting line: sha256-kbX7TXt+LMA3n0Zkjb3ZSreuhhOLAqGLqHzo2u8OhlI=
