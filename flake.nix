{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    systems.url = "github:nix-systems/default";
    flake-utils = { url = "github:numtide/flake-utils"; inputs.systems.follows = "systems"; };
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        # buildRustPackage would otherwise take nixpkgs' rustc, silently ignoring
        # the channel `rust-toolchain.toml` pins — the package and the dev shell
        # must be built by the same compiler or "works in the shell" stops
        # meaning anything.
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        };

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
        # The daemon and the CLI, without the menu bar: gpui's build script needs
        # Apple's Metal shader compiler, which cannot enter a nix closure (see
        # the xcrun shim below). The bar is built from the dev shell instead.
        net-observer = rustPlatform.buildRustPackage {
          pname = "net-observer";
          version = "0.0.0";
          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
            # duckdb comes from a git fork (gurinderu/duckdb-rs, pinned by rev in
            # Cargo.lock), and importCargoLock cannot fetch a git dependency
            # without a fixed-output hash. When the rev in Cargo.lock changes,
            # set this to lib.fakeHash, rebuild, and paste the "got:" hash.
            outputHashes = {
              "duckdb-1.10505.0" = "sha256-9tFQAE8RjfKzOUORBFfBkroSo8ykrlCV+XdK+JvgW/M=";
            };
          };
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libpcap pkgs.iconv ];
          cargoBuildFlags = [ "-p" "net-observerd" "-p" "net-observer-cli" ];
          # buildRustPackage wraps the build in `cargo-auditable` by default, and
          # that wrapper is built against NIXPKGS' rustc — not the channel
          # `rust-toolchain.toml` pins. So the default drags a second toolchain
          # into the build, and when it is not in the binary cache nix starts
          # compiling rustc from source and the whole thing dies there. The SBOM
          # it embeds buys us nothing here.
          auditable = false;
          # `DUCKDB_LIB_DIR` is deliberately NOT set: libduckdb-sys here wants
          # DuckDB 1.5.5 and nixpkgs carries 1.5.2, so linking the system library
          # would be a version mismatch. The crate builds its own engine from
          # source instead — minutes on a cold build, and correct.
          # Tests are the dev shell's job (`cargo test --all` covers the bar too,
          # which this derivation cannot build at all).
          doCheck = false;
        };
      in {
        formatter = pkgs.nixfmt-rfc-style;
        packages = {
          inherit net-observer;
          net-observerd = net-observer;
          net-observer-cli = net-observer;
          default = net-observer;
        };
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
      }))
    // {
      # Top-level, NOT inside eachDefaultSystem: a darwin module is not
      # system-scoped, and nesting it would bury it under `aarch64-darwin` and
      # make every importer name the system.
      darwinModules.default = import ./nix/darwin-module.nix { inherit self; };
    };
}
