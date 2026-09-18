# nix-darwin module for the net-observer daemon.
#
# The point of this file is that integrating the daemon into a host config costs
# one flake input and one import — the build, the launchd plumbing and the
# directory layout live here, in the project that owns them, rather than being
# re-derived in every consumer's configuration.
#
# Deliberately NOT system-scoped: a darwin module takes no `system`, so this is a
# top-level flake output. Nesting it inside `eachDefaultSystem` would bury it
# under `aarch64-darwin` and force every importer to name the system.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.net-observer;
  inherit (lib) mkEnableOption mkOption mkIf types;
in
{
  options.services.net-observer = {
    enable = mkEnableOption "the net-observer network-forensics daemon";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.net-observer;
      defaultText = "self.packages.\${system}.net-observer";
      description = ''
        The package that carries `bin/net-observerd` and `bin/net-observer-cli`
        — the flake's `net-observer` symlink join, so a host that puts this
        option into `environment.systemPackages` gets the operator's CLI next
        to the daemon. Under crate2nix each crate is its own derivation, and
        `packages.net-observerd` alone is the daemon binary only (realm
        net-observer, node #117). Taken through `self` rather than an overlay
        so a consumer gets the version pinned by its `flake.lock`.
      '';
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/etc/net-observer.toml";
      description = ''
        Path to the daemon's TOML config, passed as `--config`. Null runs it on
        its built-in defaults.

        A path named here must exist and be readable: the daemon refuses a
        `--config` it cannot read rather than falling back to defaults, because
        for a daemon that silently means binding a socket and opening a database
        nobody asked for. Every field also has a `NET_OBSERVER_*` env override.
      '';
    };

    logFile = mkOption {
      type = types.path;
      default = "/var/log/net-observerd.log";
      description = ''
        Where launchd sends the daemon's stdout and stderr. Under `/var/log`
        because launchd opens this file *before* running the program, so the
        directory has to exist already; rotation is the host's business.

        Named after the binary (`net-observerd`), NOT `net-observer.log`: the
        shell LaunchDaemon this project replaces owns `/var/log/net-observer.log`
        and both run side by side through the migration. Two launchd jobs with
        the same StandardOutPath interleave into one file, and that file is the
        behavioural oracle the rewrite is checked against — corrupting it would
        destroy the very record being migrated away from.
      '';
    };

    recordGroup = mkOption {
      type = types.str;
      default = "staff";
      description = ''
        The group that may read what the daemon writes — the record, its
        freezes, the log file — and traverse `/var/lib/observer` (realm
        net-observer, node #110). Must be the group whose gid `record_gid`
        names in the rendered config: the daemon chowns by gid, this module
        by name, and they have to agree. `staff` is the group every macOS
        console user is in.
      '';
    };
  };

  config = mkIf cfg.enable {
    launchd.daemons.net-observerd = {
      serviceConfig = {
        # The same /nix-not-yet-mounted spawn race the sing-box daemon hits: at
        # boot launchd can exec a store path before the nix volume is mounted, so
        # block on wait4path first. A daemon that dies here dies exactly when the
        # machine most needs to be observed.
        ProgramArguments = [
          "/bin/sh"
          "-c"
          "/bin/wait4path /nix/store && exec ${cfg.package}/bin/net-observerd${
            lib.optionalString (cfg.configFile != null) " --config ${cfg.configFile}"
          }"
        ];
        RunAtLoad = true;
        KeepAlive = true;
        # Matches the shell predecessor: a crash loop backs off instead of
        # spinning, and the daemon is cheap enough to restart eagerly otherwise.
        ThrottleInterval = 5;
        StandardOutPath = cfg.logFile;
        StandardErrorPath = cfg.logFile;
      };
    };

    # Root-owned and root-writable, `recordGroup` with the setgid bit and nothing
    # for the world (2750 — what the daemon's own `create_dir_all` gives under its
    # umask 027): the readers are unprivileged and reach the daemon through its
    # socket AND, for the CLI's offline `query`, through the group-readable files
    # under this directory (realm net-observer, node #110). The daemon sets the
    # same group and bit on every start; this keeps a `darwin-rebuild switch`
    # from undoing it — a plain `chmod 755` clears setgid. The socket's own mode
    # and group are the daemon's config, not this module's.
    #
    # The log file is launchd's, opened before the program runs, so its bits are
    # this module's to set: created if absent, root:recordGroup 0640, so the
    # console user reads the daemon's own account of an incident. Idempotent.
    system.activationScripts.preActivation.text = ''
      mkdir -p /var/lib/observer
      chgrp ${cfg.recordGroup} /var/lib/observer
      chmod 2750 /var/lib/observer
      touch ${toString cfg.logFile}
      chgrp ${cfg.recordGroup} ${toString cfg.logFile}
      chmod 0640 ${toString cfg.logFile}
    '';
  };
}
