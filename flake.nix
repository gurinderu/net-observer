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

        # One cargoLock for every package below: importCargoLock vendors the
        # whole lock file regardless of which -p graph is built, so the vendor
        # derivation is shared.
        cargoLock = {
          lockFile = ./Cargo.lock;
          # duckdb comes from a git fork (gurinderu/duckdb-rs, pinned by rev in
          # Cargo.lock), and importCargoLock cannot fetch a git dependency
          # without a fixed-output hash. When the rev in Cargo.lock changes,
          # set this to pkgs.lib.fakeHash, rebuild, and paste the "got:" hash.
          outputHashes = {
            "duckdb-1.10505.0" = "sha256-9tFQAE8RjfKzOUORBFfBkroSo8ykrlCV+XdK+JvgW/M=";
          };
        };
        # The daemon and the CLI, without the menu bar — not because the bar is
        # unbuildable any more (see net-observer-bar below), but so the
        # network-critical daemon closure does not rebuild when only UI
        # dependencies move.
        net-observer = rustPlatform.buildRustPackage {
          pname = "net-observer";
          version = "0.0.0";
          src = ./.;
          inherit cargoLock;
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
          # Tests are the dev shell's job (`cargo test --all`).
          doCheck = false;
        };
        # The menu bar as a normal nix package. Buildable at all because the
        # workspace pins gpui with `runtime_shaders` (see Cargo.toml): without
        # that feature gpui's build script shells out to `xcrun -sdk macosx
        # metal`, and Apple's Metal shader compiler ships only inside Xcode
        # and cannot be redistributed, so it can never enter a nix closure.
        # With the feature the only build-time codegen left is bindgen over
        # dispatch.h — hence bindgenHook (libclang + SDK include paths).
        # Its own derivation, darwin-only by nature (AppKit/NSStatusItem):
        # a pure IPC-socket client of net-observerd, no pcap, no DuckDB.
        net-observer-bar = rustPlatform.buildRustPackage {
          pname = "net-observer-bar";
          version = "0.0.0";
          src = ./.;
          inherit cargoLock;
          nativeBuildInputs = [ rustPlatform.bindgenHook ];
          buildInputs = [ pkgs.iconv ];
          cargoBuildFlags = [ "-p" "net-observer-bar" ];
          # Same rationale as the daemon package above.
          auditable = false;
          doCheck = false;
          meta.mainProgram = "net-observer-bar";
        };
      in {
        formatter = pkgs.nixfmt-rfc-style;
        packages = {
          inherit net-observer net-observer-bar;
          net-observerd = net-observer;
          net-observer-cli = net-observer;
          default = net-observer;
        };
        devShells.default = pkgs.mkShell {
          name = "net-observer-dev";
          packages = [
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
