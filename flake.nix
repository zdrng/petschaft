{
  description = "petschaft: SSH login, git commit signing and APK signing with a Trezor Safe 7";

  # Stable nixpkgs release branch; the exact revision is pinned in flake.lock.
  # Consumers: `inputs.petschaft.inputs.nixpkgs.follows = "nixpkgs";` (docs/nix.md).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Development and tests only: the helper environment plus pytest.
      devPython =
        pkgs:
        pkgs.python3.withPackages (
          ps:
          [
            ps.trezor
            ps.cryptography
            ps.pytest
          ]
          ++ ps.trezor.optional-dependencies.ble
        );

      # Module evaluation checks (eval only: on Darwin nothing for Linux is built).
      checkSettings = {
        transport = "auto";
        defaults.passphrase = "ask";
        identity = [
          {
            name = "git";
            uri = "ssh://check@git-signing";
            curve = "ed25519";
          }
        ];
      };
      # Dummy key line: only strings are compared, nothing is verified.
      checkSigningKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvalCheckDummyKeyNotARealKey000000000000000 git";

      nixosCheckSystem =
        extraModules:
        nixpkgs.lib.nixosSystem {
          modules = [
            self.nixosModules.default
            {
              nixpkgs.hostPlatform = "x86_64-linux";
              boot.loader.grub.enable = false;
              fileSystems."/" = {
                device = "/dev/disk/by-label/nixos";
                fsType = "ext4";
              };
              system.stateVersion = "26.05";
              programs.petschaft.enable = true;
            }
          ]
          ++ extraModules;
        };

      nixosModuleCheck =
        let
          full = nixosCheckSystem [
            {
              programs.petschaft = {
                settings = checkSettings;
                agent.enable = true;
                git = {
                  enable = true;
                  signingKey = checkSigningKey;
                  allowedSigners = [ ''check@example.org namespaces="git" ${checkSigningKey}'' ];
                };
              };
            }
          ];
          withOverlay = nixosCheckSystem [ { nixpkgs.overlays = [ self.overlays.default ]; } ];
          missingKey = nixosCheckSystem [ { programs.petschaft.git.enable = true; } ];

          c = full.config;
          pkg = c.programs.petschaft.package;
          etc = c.environment.etc;
          gitconfig = etc.gitconfig.text;
          agentService = c.systemd.user.services.petschaft-agent;
          failed = cfg: map (a: a.message) (lib.filter (a: !a.assertion) cfg.config.assertions);
          # Compare without string context (regex matching refuses store paths).
          has =
            needle: hay:
            lib.hasInfix (builtins.unsafeDiscardStringContext needle) (builtins.unsafeDiscardStringContext hay);
          check = cond: msg: if cond then true else throw "nixos-module check: ${msg}";
        in
        assert check (failed full == [ ]) "unexpected failed assertions: ${toString (failed full)}";
        assert check (lib.any (lib.hasInfix "requires programs.petschaft.git.signingKey") (
          failed missingKey
        )) "git.enable without signingKey must fail an assertion";
        assert check (
          withOverlay.config.programs.petschaft.package.drvPath == pkg.drvPath
        ) "package differs with and without overlays.default";
        assert check (lib.elem pkg c.environment.systemPackages) "package not in systemPackages";
        assert check (lib.elem full.pkgs.trezor-udev-rules c.services.udev.packages)
          "trezor udev rules missing";
        assert check (lib.elem full.pkgs.libfido2 c.services.udev.packages) "libfido2 udev rules missing";
        assert check c.hardware.bluetooth.enable "bluetooth not enabled";
        assert check (has ''program = "${lib.getExe pkg}"'' gitconfig) "gpg.ssh.program not set";
        assert check (has ''signingkey = "key::${checkSigningKey}"'' gitconfig) "user.signingkey not set";
        assert check (has ''allowedSignersFile = "/etc/petschaft/allowed_signers"'' gitconfig)
          "allowedSignersFile not set";
        assert check (has "gpgsign = true" gitconfig) "gpgsign not set";
        assert check (has ''namespaces="git"''
          etc."petschaft/allowed_signers".text
        ) "allowed_signers content";
        assert check (agentService.serviceConfig.ExecStart == "${lib.getExe pkg} agent") "agent ExecStart";
        assert check (lib.elem "default.target" agentService.wantedBy) "agent not wanted by default.target";
        assert check (agentService.serviceConfig.Restart == "on-failure") "agent Restart";
        assert check (agentService.serviceConfig.RuntimeDirectoryMode == "0700") "agent runtime dir mode";
        assert check agentService.serviceConfig.NoNewPrivileges "agent NoNewPrivileges";
        assert check (
          !(withOverlay.config.systemd.user.services ? petschaft-agent)
        ) "agent service must be off by default";
        {
          package = pkg.drvPath;
          config = etc."petschaft/config.toml".source.drvPath;
          etc = c.system.build.etc.drvPath;
          udev = map (p: p.drvPath) c.services.udev.packages;
          agent = c.systemd.user.units."petschaft-agent.service".unit.drvPath;
          toplevel = c.system.build.toplevel.drvPath;
        };

      # nix-darwin is not an input (consumers bring their own), so the options used
      # here are stubbed (environment.* with nix-darwin's types, launchd loosely).
      darwinModuleCheck =
        let
          pkgs = nixpkgs.legacyPackages.aarch64-darwin;
          darwinEval =
            agentConfig:
            lib.evalModules {
              modules = [
                self.darwinModules.default
                {
                  options.environment = {
                    systemPackages = lib.mkOption { type = lib.types.listOf lib.types.package; };
                    etc = lib.mkOption {
                      type = lib.types.attrsOf (
                        lib.types.submodule { options.source = lib.mkOption { type = lib.types.path; }; }
                      );
                      default = { };
                    };
                  };
                  options.launchd.user.agents = lib.mkOption {
                    type = lib.types.attrsOf (
                      lib.types.submodule {
                        options.serviceConfig = lib.mkOption { type = lib.types.attrsOf lib.types.anything; };
                      }
                    );
                    default = { };
                  };
                  config = {
                    _module.args.pkgs = pkgs;
                    programs.petschaft = {
                      enable = true;
                      settings = checkSettings;
                      agent = agentConfig;
                    };
                  };
                }
              ];
            };
          c = (darwinEval { enable = true; }).config;
          withLog =
            (darwinEval {
              enable = true;
              logFile = "/Library/Logs/petschaft-check/agent.log";
            }).config;
          off = (darwinEval { }).config;
          pets = lib.getExe c.programs.petschaft.package;
          agent = c.launchd.user.agents.petschaft-agent.serviceConfig;
          agentWithLog = withLog.launchd.user.agents.petschaft-agent.serviceConfig;
          check = cond: msg: if cond then true else throw "darwin-module check: ${msg}";
        in
        assert check (lib.elem c.programs.petschaft.package c.environment.systemPackages)
          "package not in systemPackages";
        assert check (lib.last agent.ProgramArguments == pets) "agent ProgramArguments (default log)";
        assert check (lib.hasInfix "Library/Logs/petschaft-agent.log" (
          lib.elemAt agent.ProgramArguments 2
        )) "agent default log path";
        assert check (
          agentWithLog.ProgramArguments == [
            pets
            "agent"
          ]
        ) "agent ProgramArguments (logFile)";
        assert check (
          agentWithLog.StandardErrorPath == "/Library/Logs/petschaft-check/agent.log"
        ) "agent StandardErrorPath";
        assert check (agent.RunAtLoad && agent.KeepAlive) "agent RunAtLoad/KeepAlive";
        assert check (!(agent ? StandardErrorPath)) "no StandardErrorPath without logFile";
        assert check (off.launchd.user.agents == { }) "agent must be off by default";
        {
          package = c.programs.petschaft.package.drvPath;
          config = c.environment.etc."petschaft/config.toml".source.drvPath;
          agent = builtins.toJSON agent;
        };

      evalCheck =
        pkgs: name: result:
        pkgs.writeText name (builtins.unsafeDiscardStringContext (builtins.toJSON result));
    in
    {
      packages = forAllSystems (pkgs: {
        petschaft = pkgs.callPackage ./nix/package.nix { };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.petschaft;

        # README illustrations (docs/img/render.py), rendered with only the font files
        # named here. Zoom 1.25: the README shows them 560 px wide, so 1150 px PNGs stay
        # sharp on 2x screens. Update the committed PNGs from the repository root with:
        #   nix build .#readme-images -o result-img && install -m 644 result-img/*.png docs/img/ && rm result-img
        readme-images =
          pkgs.runCommand "petschaft-readme-images"
            {
              nativeBuildInputs = [
                pkgs.python3
                pkgs.resvg
              ];
            }
            ''
              python3 -I ${./docs/img/render.py} svg
              mkdir -p $out
              for f in svg/*.svg; do
                resvg --skip-system-fonts \
                  --use-font-file ${pkgs.inter}/share/fonts/truetype/Inter.ttc \
                  --use-font-file ${pkgs.jetbrains-mono}/share/fonts/truetype/JetBrainsMonoNL-Regular.ttf \
                  --zoom 1.25 "$f" "$out/$(basename "''${f%.svg}").png"
              done
            '';

        # Logo variants (docs/img/logo/build.py): variant SVGs + PNGs, comparison sheet and the
        # README icon; labels on the sheet in Inter from nixpkgs only. Update with:
        #   nix build .#readme-logos -o result-logo && install -m 644 result-logo/* docs/img/logo/ && rm result-logo
        readme-logos =
          pkgs.runCommand "petschaft-readme-logos"
            {
              nativeBuildInputs = [
                pkgs.python3
                pkgs.resvg
              ];
            }
            ''
              python3 -I ${./docs/img/logo/build.py} $out
              for f in $out/*.svg; do
                resvg --skip-system-fonts \
                  --use-font-file ${pkgs.inter}/share/fonts/truetype/Inter.ttc \
                  "$f" "''${f%.svg}.png"
              done
              rm $out/comparison.svg $out/readme-icon.svg
            '';
      });

      overlays.default = final: _prev: {
        petschaft = final.callPackage ./nix/package.nix { };
      };

      nixosModules.default = ./nix/nixos-module.nix;
      darwinModules.default = ./nix/darwin-module.nix;

      # nix flake check: the central gate
      checks = forAllSystems (
        pkgs:
        let
          petschaft = self.packages.${pkgs.stdenv.hostPlatform.system}.petschaft;
        in
        {
          # Build + all Rust tests (nextest)
          inherit petschaft;

          clippy = petschaft.overrideAttrs (old: {
            pname = "petschaft-clippy";
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
            buildPhase = ''
              runHook preBuild
              cargo clippy --offline --workspace --all-targets -- -D warnings
              # compile_fail doctests prove that invalid states cannot be constructed
              cargo test --offline --workspace --doc
              runHook postBuild
            '';
            doCheck = false;
            installPhase = "touch $out";
          });

          fmt =
            pkgs.runCommand "petschaft-fmt"
              {
                nativeBuildInputs = [
                  pkgs.rustfmt
                  pkgs.ruff
                  pkgs.nixfmt
                ];
              }
              ''
                cd ${self}
                find crates -name '*.rs' -print0 | xargs -0 rustfmt --check --edition 2024
                ruff format --no-cache --check --config helper/ruff.toml helper
                find . -name '*.nix' -print0 | xargs -0 nixfmt --check
                touch $out
              '';

          helper =
            pkgs.runCommand "petschaft-helper-tests"
              {
                nativeBuildInputs = [
                  (devPython pkgs)
                  pkgs.ruff
                ];
              }
              ''
                cp -r ${self}/helper ./helper
                chmod -R u+w helper
                ruff check --no-cache --config helper/ruff.toml helper
                HOME=$TMPDIR python3 -I -m pytest -q -p no:cacheprovider helper
                touch $out
              '';

          nixos-module = evalCheck pkgs "petschaft-nixos-module-eval" nixosModuleCheck;
          darwin-module = evalCheck pkgs "petschaft-darwin-module-eval" darwinModuleCheck;
        }
      );

      # nix develop: development shell
      devShells = forAllSystems (
        pkgs:
        let
          inherit (self.packages.${pkgs.stdenv.hostPlatform.system}.petschaft)
            helperPython
            apksigner
            aapt2
            ;
        in
        {
          default = pkgs.mkShell {
            packages = [
              # Rust
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
              pkgs.cargo-nextest
              pkgs.cargo-deny
              # Fuzzing (fuzz/, docs/testing.md): stable rustc with RUSTC_BOOTSTRAP=1.
              pkgs.cargo-fuzz

              # Trezor access (trezorctl + trezorlib) and helper tests
              (devPython pkgs)
              pkgs.ruff

              # OpenSSH with FIDO2 (the one shipped with macOS has no FIDO2 support)
              pkgs.openssh

              pkgs.nixfmt
            ];

            env = {
              RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
              # Helper for development builds; release builds get fixed store paths.
              PETSCHAFT_HELPER_PYTHON = "${helperPython}/bin/python3";
              # FIDO2-capable OpenSSH (a store path, so fixed in development builds too).
              PETSCHAFT_OPENSSH_BIN = "${pkgs.openssh}/bin";
              # apksigner with an EC-capable JRE (nix/package.nix); needed by `pets apk`
              # and the petschaft-apk tests.
              PETSCHAFT_APKSIGNER = "${apksigner}/bin/apksigner";
              PETSCHAFT_OPENSSL = "${pkgs.lib.getBin pkgs.openssl}/bin/openssl";
            }
            # aapt2 (not available for aarch64-linux in nixpkgs): `pets apk sign` and its tests.
            // (if aapt2 != null then { PETSCHAFT_AAPT2 = aapt2; } else { PETSCHAFT_NO_AAPT2 = "1"; });
            shellHook = ''
              export PETSCHAFT_HELPER_SCRIPT="$PWD/helper/petschaft_helper.py"
            '';
          };
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
