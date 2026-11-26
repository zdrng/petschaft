# NixOS module: programs.petschaft
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

    udev = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Install udev rules that give the logged-in user access to the Trezor
        over USB (`pkgs.trezor-udev-rules`) and to FIDO2 authenticators over
        USB (libfido2's rules, used by OpenSSH for `sk-*` keys).
      '';
    };

    bluetooth = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable BlueZ (`hardware.bluetooth.enable`, as a `mkDefault`) so `pets`
        can reach the Trezor over Bluetooth.
      '';
    };

    agent.enable = lib.mkEnableOption ''
      the SSH agent `pets agent` as the systemd user service
      `petschaft-agent` (socket {file}`$XDG_RUNTIME_DIR/petschaft/agent.sock`).
      It serves slip13 identities that have `public_key` and `host_keys`; point
      ssh at it per host with `IdentityAgent` (see `docs/agent.md`). Run
      `pets pair` once in a terminal first'';

    git = {
      enable = lib.mkEnableOption ''
        system-wide git signing with petschaft: sets `gpg.format = ssh`,
        `gpg.ssh.program`, `user.signingkey`, `commit.gpgsign` and
        `tag.gpgsign` in {file}`/etc/gitconfig` (via `programs.git`).
        Per-user or per-repository git config still takes precedence'';

      signingKey = lib.mkOption {
        type = lib.types.nullOr lib.types.singleLineStr;
        default = null;
        example = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… git";
        description = ''
          The OpenSSH public key line printed by `pets pubkey <name>`, without
          a `key::` prefix (the module adds it). Public data.
        '';
      };

      allowedSigners = lib.mkOption {
        type = lib.types.listOf lib.types.singleLineStr;
        default = [ ];
        example = [ ''alice@example.org namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…'' ];
        description = ''
          Lines of an OpenSSH allowed signers file (see ssh-keygen(1),
          "ALLOWED SIGNERS"). When non-empty they are written to
          {file}`/etc/petschaft/allowed_signers` and git's
          `gpg.ssh.allowedSignersFile` points there, so `git log --show-signature`
          and `git verify-commit` can check signatures.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = cfg.git.enable -> cfg.git.signingKey != null;
            message = ''
              programs.petschaft.git.enable requires programs.petschaft.git.signingKey:
              set it to the line printed by `pets pubkey <name>`.
            '';
          }
          {
            assertion = cfg.git.signingKey == null || !lib.hasPrefix "key::" cfg.git.signingKey;
            message = ''
              programs.petschaft.git.signingKey must be the bare OpenSSH key line
              (e.g. "ssh-ed25519 AAAA… git"); the module adds the "key::" prefix itself.
            '';
          }
          {
            assertion = cfg.git.allowedSigners != [ ] -> cfg.git.enable;
            message = "programs.petschaft.git.allowedSigners is only used with programs.petschaft.git.enable = true.";
          }
        ];

        environment.systemPackages = [ cfg.package ];
      }

      (lib.mkIf (cfg.settings != { }) {
        environment.etc."petschaft/config.toml".source =
          settingsFormat.generate "petschaft-config.toml" cfg.settings;
      })

      (lib.mkIf cfg.udev {
        services.udev.packages = [
          pkgs.trezor-udev-rules
          pkgs.libfido2
        ];
        # trezor-udev-rules assigns its devices to this group (access for the
        # logged-in user comes from TAG+="uaccess"); create it so udev does not
        # warn about an unknown group.
        users.groups.trezord = { };
      })

      (lib.mkIf cfg.bluetooth {
        hardware.bluetooth.enable = lib.mkDefault true;
      })

      (lib.mkIf cfg.git.enable {
        programs.git = {
          enable = true;
          config = {
            gpg = {
              format = "ssh";
              ssh = {
                program = pets;
              }
              // lib.optionalAttrs (cfg.git.allowedSigners != [ ]) {
                allowedSignersFile = "/etc/petschaft/allowed_signers";
              };
            };
            user.signingkey = "key::${cfg.git.signingKey}";
            commit.gpgsign = true;
            tag.gpgsign = true;
          };
        };
      })

      (lib.mkIf cfg.agent.enable {
        systemd.user.services.petschaft-agent = {
          description = "petschaft SSH agent (Trezor)";
          documentation = [ "https://github.com/zdrng/petschaft/blob/main/docs/agent.md" ];
          wantedBy = [ "default.target" ];
          serviceConfig = {
            ExecStart = "${pets} agent";
            Restart = "on-failure";
            RestartSec = 5;
            # $XDG_RUNTIME_DIR/petschaft, 0700, removed when the service stops (so no
            # stale socket is left behind).
            RuntimeDirectory = "petschaft";
            RuntimeDirectoryMode = "0700";
            # Conservative hardening that keeps USB (/dev is untouched), Bluetooth and
            # the Secret Service (D-Bus sockets can be connected to on a read-only
            # file system) working. See docs/nix.md.
            NoNewPrivileges = true;
            PrivateTmp = true;
            ProtectSystem = "strict";
            ReadWritePaths = [ "%t/petschaft" ];
          };
        };
      })

      (lib.mkIf (cfg.git.enable && cfg.git.allowedSigners != [ ]) {
        environment.etc."petschaft/allowed_signers".text = lib.concatLines cfg.git.allowedSigners;
      })
    ]
  );
}
