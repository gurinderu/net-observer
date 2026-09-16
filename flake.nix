{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    systems.url = "github:nix-systems/default";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
    rust-overlay.url = "github:oxalica/rust-overlay";
    # crate2nix's own flake declares a `nixpkgs` input, so follow ours: one
    # nixpkgs evaluation for the whole closure instead of two.
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crate2nix,
      ...
    }:
    (flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        # buildRustCrate would otherwise take nixpkgs' rustc, silently ignoring
        # the channel `rust-toolchain.toml` pins — the package and the dev shell
        # must be built by the same compiler or "works in the shell" stops
        # meaning anything. Only `buildRustCrateForPkgs` below is pointed at
        # `rust`; `pkgs.rustc`/`pkgs.cargo` themselves are left alone, or every
        # nixpkgs-native Rust tool (bindgen among them) would rebuild against
        # our toolchain too.

        # (realm net-observer, node #76) — one derivation per crate instead of
        # one per package, so a change rebuilds only the crate that changed and
        # its dependents.
        #
        # (realm net-observer, node #95) — Cargo.nix is CHECKED IN, generated
        # by the crate2nix CLI (`crate2nix generate` in the dev shell), not
        # produced at evaluation time. The eval-time generator vendors the
        # duckdb-rs git fork without its workspace root, so the fork's
        # `{ workspace = true }` inheritance breaks `cargo metadata` there;
        # the CLI runs the real cargo against the full git checkout, where
        # inheritance resolves. The price is a file that must be regenerated
        # whenever Cargo.lock changes — CI diffs it against a fresh
        # generation and fails when it is stale. The gains: no import from
        # derivation, no network at evaluation, and every system's attributes
        # evaluate from any host. crate-hashes.json beside it holds the hash
        # of the fork's source (not in Cargo.lock), which pkgs.fetchgit needs.
        cargoNix = import ./Cargo.nix { inherit pkgs buildRustCrateForPkgs; };

        # (realm net-observer, node #80) — overrides added here are the ones
        # evidence on this machine supports; anything that can only be
        # confirmed by a macOS build is left out and named as a risk instead.
        crateOverrides = {
          # gpui's build script runs bindgen over dispatch.h (libclang + SDK
          # include paths). The workspace pins gpui's `runtime_shaders`
          # feature (see Cargo.toml), which keeps the OTHER build-time
          # dependency — `xcrun -sdk macosx metal`, needing the Metal
          # Toolchain that only ships inside a full Xcode — out of the build
          # entirely; bindgen is what is left. crate2nix resolves features
          # from Cargo.toml/Cargo.lock, so `runtime_shaders` reaches the
          # generated Cargo.nix without any help from this file.
          gpui = _attrs: { nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ]; };
          # libduckdb-sys builds DuckDB from source (the `bundled` feature,
          # via the `cc` crate) and needs nothing beyond the C++ compiler
          # stdenv already provides: `default-features = false` on the
          # workspace's `duckdb` dependency turns off libduckdb-sys's
          # `pkg-config` feature along with the rest of its defaults, so its
          # build.rs never calls pkg-config and no override belongs here.
          # `DUCKDB_LIB_DIR` is deliberately never set anywhere in this flake:
          # nixpkgs' DuckDB is a different version from what this fork wants,
          # so linking the system library would be a version mismatch — the
          # bundled, built-from-source engine is the sanctioned exception.
          #
          # No workspace crate depends on a `pcap` crate (the pcap ring runs
          # `tcpdump` as a child process at runtime, not a build-time link),
          # so libpcap is not carried forward from the old buildRustPackage
          # flake. `iconv` — needed by *something* in the darwin link step on
          # the old flake, evidence this Linux box cannot narrow further — is
          # kept, conservatively, on the three binaries rather than guessed
          # onto a specific library crate.
          net-observerd = _attrs: { buildInputs = [ pkgs.iconv ]; };
          "net-observer-cli" = _attrs: { buildInputs = [ pkgs.iconv ]; };
          "net-observer-bar" = _attrs: { buildInputs = [ pkgs.iconv ]; };
        };
        buildRustCrateForPkgs =
          p:
          p.buildRustCrate.override {
            rustc = rust;
            cargo = rust;
            defaultCrateOverrides = p.defaultCrateOverrides // crateOverrides;
          };

        workspace = cargoNix.workspaceMembers;
        net-observerd = workspace."net-observerd".build;
        net-observer-cli = workspace."net-observer-cli".build;
        # Darwin-only by nature (AppKit/NSStatusItem), and its own derivation:
        # a pure IPC-socket client of net-observerd, no pcap, no DuckDB — its
        # store path does not move when the daemon's dependencies do, and vice
        # versa.
        net-observer-bar = workspace."net-observer-bar".build.overrideAttrs (_old: {
          meta.mainProgram = "net-observer-bar";
        });
        # Previously `net-observerd` and `net-observer-cli` were aliases of one
        # `buildRustPackage` derivation holding both binaries. crate2nix builds
        # each crate as its own derivation, so `net-observer` now joins the two
        # built outputs instead of being the thing they alias.
        net-observer = pkgs.symlinkJoin {
          name = "net-observer";
          paths = [
            net-observerd
            net-observer-cli
          ];
        };
      in
      {
        formatter = pkgs.nixfmt-rfc-style;
        packages = {
          inherit
            net-observer
            net-observerd
            net-observer-cli
            net-observer-bar
            ;
          default = net-observer;
        };
        # The two workspace crates with no Apple-only dependency, built through
        # the same Cargo.nix as the darwin packages: the one place the
        # crate2nix route (buildRustCrate, the bundled DuckDB engine compiled
        # by libduckdb-sys's build script) is exercised on a Linux host.
        checks = {
          store-crate = workspace."store".build;
          triggers-crate = workspace."triggers".build;
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
            # The generator of the checked-in Cargo.nix, at the rev the flake
            # pins, so `crate2nix generate` here reproduces the file CI diffs.
            crate2nix.packages.${system}.default
          ];
          # duckdb crate links the system lib when DUCKDB_LIB_DIR is set; else it builds bundled.
        };
      }
    ))
    // {
      # Top-level, NOT inside eachDefaultSystem: a darwin module is not
      # system-scoped, and nesting it would bury it under `aarch64-darwin` and
      # make every importer name the system.
      darwinModules.default = import ./nix/darwin-module.nix { inherit self; };
    };
}
