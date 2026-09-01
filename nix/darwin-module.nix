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
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.net-observerd;
      defaultText = "self.packages.\${system}.net-observerd";
      description = ''
        The daemon package. Defaults to this flake's own build, taken through
        `self` rather than an overlay so a consumer gets the version pinned by
        its `flake.lock` and not whatever a nixpkgs overlay happens to hold.
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

    # Root-owned and root-writable; the readers are unprivileged and reach the
    # daemon through its socket, never through these files. The socket's own mode
    # and owner are the daemon's config, not this module's.
    system.activationScripts.preActivation.text = ''
      mkdir -p /var/lib/observer
      chmod 755 /var/lib/observer
    '';
  };
}
