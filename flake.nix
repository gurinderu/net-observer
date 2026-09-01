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

        # gpui compiles its Metal shaders by calling `xcrun -sdk macosx metal`,
        # and the `xcrun` nix puts on PATH is xcbuild's reimplementation, which
        # has no Metal compiler — so `cargo build -p net-observer-bar` fails with
        # "missing Metal Toolchain" even on a machine where Xcode ships one.
        #
        # The compiler cannot come from nixpkgs: Apple does not permit
        # redistributing it. Exporting DEVELOPER_DIR for the whole shell would
        # find it but also repoint cc/ld at Xcode's SDK, and linking against the
        # nix toolchain then fails. So shim ONLY xcrun: Apple's developer tools
        # resolve from Xcode, everything else stays on nix.
        #
        # Falls through untouched when Xcode is absent, so the shell still works
        # on a machine that simply cannot build the GUI.
        metalXcrun = pkgs.writeShellScriptBin "xcrun" ''
          XCODE_DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
          if [ -d "$XCODE_DEVELOPER_DIR" ]; then
            export DEVELOPER_DIR="$XCODE_DEVELOPER_DIR"
          fi
          exec /usr/bin/xcrun "$@"
        '';
      in {
        formatter = pkgs.nixfmt-rfc-style;
        devShells.default = pkgs.mkShell {
          name = "net-observer-dev";
          # metalXcrun goes FIRST: it must shadow xcbuild's xcrun on PATH.
          packages = [
            metalXcrun
            rust
            pkgs.bashInteractive
            pkgs.pkg-config
            pkgs.duckdb
            pkgs.libpcap
            pkgs.iconv
          ];
          # duckdb crate links the system lib when DUCKDB_LIB_DIR is set; else it builds bundled.
        };
      });
}
