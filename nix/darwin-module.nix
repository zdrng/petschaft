# nix-darwin module: programs.petschaft
#
# Git signing is not configured system-wide here: there is no single system
# gitconfig on macOS. Apple's git (/usr/bin/git) reads /etc/gitconfig plus the
# Xcode / Command Line Tools one; nixpkgs' git on Darwin reads only the
# etc/gitconfig inside its own store path. Users run the four
# `git config --global` lines from docs/nix.md instead.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.petschaft;
  settingsFormat = pkgs.formats.toml { };
  pets = lib.getExe cfg.package;
in
{
  options.programs.petschaft = {
    enable = lib.mkEnableOption "petschaft (`pets`), SSH login and git signing with a Trezor";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.petschaft or (pkgs.callPackage ./package.nix { });
      defaultText = lib.literalExpression "pkgs.petschaft or (pkgs.callPackage \"\${petschaft}/nix/package.nix\" { })";
      description = ''
        The petschaft package. Defaults to `pkgs.petschaft` when the flake's
        `overlays.default` is applied, otherwise it is built from the flake's
        source against the system's nixpkgs.
      '';
    };

    settings = lib.mkOption {
      inherit (settingsFormat) type;
      default = { };
      example = lib.literalExpression ''
        {
          transport = "auto";
          defaults.passphrase = "ask";
          identity = [
            {
              name = "git";
              uri = "ssh://alice@git-signing";
              curve = "ed25519";
              fingerprint = "SHA256:…";
            }
          ];
        }
      '';
      description = ''
        System-wide petschaft configuration, written to
        {file}`/etc/petschaft/config.toml` when non-empty. `pets` reads it
        when the user has no {file}`~/.config/petschaft/config.toml`.
        See `docs/architecture.md` for the schema. The file is world-readable
        in the Nix store: it must only contain public data (identity URIs,
        curves, fingerprints, public keys, APK signing certificates), which is
        all the schema has.
      '';
    };

    agent = {
      enable = lib.mkEnableOption ''
        the SSH agent `pets agent` as the launchd user agent `petschaft-agent`
        (socket {file}`~/Library/Application Support/petschaft/agent.sock`), started
        at login for every user. It serves slip13 identities that have `public_key`
        and `host_keys`; point ssh at it per host with `IdentityAgent` (see
        `docs/agent.md`). Run `pets pair` once in a terminal first'';

      logFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/Library/Logs/petschaft/agent.log";
        description = ''
          Log file of the agent (stdout and stderr). `null`: each user's
          {file}`~/Library/Logs/petschaft-agent.log` (appended through
          {command}`/bin/sh`, because launchd does not expand `~`; rotated when the
          agent starts if it is larger than 1 MiB, keeping 3 old files). A file set
          here is not rotated. Do not put it in
          a world-writable directory such as {file}`/tmp`: launchd follows symlinks
          when it opens the file.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      { environment.systemPackages = [ cfg.package ]; }

      (lib.mkIf (cfg.settings != { }) {
        environment.etc."petschaft/config.toml".source =
          settingsFormat.generate "petschaft-config.toml" cfg.settings;
      })

      (lib.mkIf cfg.agent.enable {
        launchd.user.agents.petschaft-agent.serviceConfig = {
          ProgramArguments =
            if cfg.agent.logFile == null then
              [
                "/bin/sh"
                "-c"
                # Rotated by the user's own shell at start, not by newsyslog: newsyslog
                # runs as root (file operations in a user-writable directory) and can
                # neither copy-truncate nor safely signal the agent, which keeps the
                # file open. Log volume while running is bounded by the agent's rate
                # limit on client-triggered lines.
                ''
                  log="$HOME/Library/Logs/petschaft-agent.log"
                  if [ "$(/usr/bin/stat -f %z "$log" 2>/dev/null || echo 0)" -gt 1048576 ]; then
                    mv -f "$log.2" "$log.3" 2>/dev/null
                    mv -f "$log.1" "$log.2" 2>/dev/null
                    mv -f "$log" "$log.1"
                  fi
                  exec "$0" agent >>"$log" 2>&1
                ''
                pets
              ]
            else
              [
                pets
                "agent"
              ];
          RunAtLoad = true;
          # Restarted whenever it exits (it only exits on errors or when killed).
          KeepAlive = true;
          ProcessType = "Interactive";
        }
        // lib.optionalAttrs (cfg.agent.logFile != null) {
          StandardOutPath = cfg.agent.logFile;
          StandardErrorPath = cfg.agent.logFile;
        };
      })
    ]
  );
}
