{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    systems.url = "github:nix-systems/default";
    flake-utils = { url = "github:numtide/flake-utils"; inputs.systems.follows = "systems"; };
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in {
        formatter = pkgs.nixfmt-rfc-style;
        devShells.default = pkgs.mkShell {
          name = "net-observer-dev";
          packages = [ rust pkgs.bashInteractive pkgs.pkg-config pkgs.duckdb pkgs.libpcap pkgs.iconv ];
          # duckdb crate links the system lib when DUCKDB_LIB_DIR is set; else it builds bundled.
        };
      });
}
