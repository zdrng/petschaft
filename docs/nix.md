# Using petschaft from a NixOS or nix-darwin configuration

The flake exports:

| Output | Content |
|---|---|
| `packages.<system>.{petschaft,default}` | the `pets` binary with the Python helper, a FIDO2-capable OpenSSH, an EC-capable `apksigner` and `aapt2` (not on aarch64-linux) baked in as fixed store paths |
| `overlays.default` | adds `pkgs.petschaft` (built against *your* nixpkgs) |
| `nixosModules.default` | `programs.petschaft` for NixOS |
| `darwinModules.default` | `programs.petschaft` for nix-darwin |

Systems: `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`, `x86_64-darwin`. No Home Manager needed.

## Flake input

```nix
inputs = {
  nixpkgs.url = "github:NixOS/nixpkgs/<your branch>"; # whatever your system already uses
  petschaft.url = "github:zdrng/petschaft";
  petschaft.inputs.nixpkgs.follows = "nixpkgs";
};
```

With `follows`, petschaft is built against your nixpkgs, whichever branch that is. The
flake's own `flake.lock` (used only without `follows`) pins a revision of the
`nixpkgs-26.05-darwin` branch. The helper is written for
trezorlib `>= 0.20.2, < 0.21`; if your nixpkgs has a different `python3.pkgs.trezor`, the
build stops with an error saying so. Then either drop the `follows` line (petschaft uses
its own pinned nixpkgs) or move to a nixpkgs with a supported trezorlib.

The overlay is optional: without it, the modules build the package from the flake source
against the system's `pkgs`; with it, they use `pkgs.petschaft`. Both give the same
derivation.

## NixOS

```nix
# flake.nix
outputs = { nixpkgs, petschaft, ... }: {
  nixosConfigurations.desktop = nixpkgs.lib.nixosSystem {
    modules = [
      ./configuration.nix
      petschaft.nixosModules.default
      # optional: { nixpkgs.overlays = [ petschaft.overlays.default ]; }
    ];
  };
};
```

```nix
# configuration.nix
{
  programs.petschaft = {
    enable = true;

    # -> /etc/petschaft/config.toml (schema: docs/architecture.md#configuration)
    settings = {
      transport = "auto";
      defaults.passphrase = "standard"; # "ask" needs passphrase protection on the Trezor
      identity = [
        {
          name = "git";
          uri = "ssh://alice@git-signing";
          curve = "ed25519";
          fingerprint = "SHA256:…"; # from `pets pubkey git`
        }
        {
          name = "homelab";
          kind = "fido2";
          algorithm = "ed25519-sk";
        }
      ];
    };

    # udev = true;       # default: Trezor + FIDO2 (libfido2) udev rules
    # bluetooth = true;  # default: hardware.bluetooth.enable = mkDefault true

    git = {
      enable = true;
      # the line printed by `pets pubkey git` (no "key::" prefix)
      signingKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… git";
      allowedSigners = [
        ''alice@example.org namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…''
      ];
    };
  };
}
```

### Options

| Option | Default | Effect |
|---|---|---|
| `enable` | `false` | installs the package in `environment.systemPackages` |
| `package` | `pkgs.petschaft` or built from the flake | the package to use |
| `settings` | `{ }` | freeform TOML (identities incl. an APK identity's `certificate`); when non-empty written to `/etc/petschaft/config.toml` |
| `udev` | `true` | `services.udev.packages = [ trezor-udev-rules libfido2 ]`, creates group `trezord` (the Trezor rules use it; the logged-in user gets access through `uaccess`) |
| `bluetooth` | `true` | `hardware.bluetooth.enable = lib.mkDefault true` (Trezor over Bluetooth) |
| `git.enable` | `false` | system-wide `/etc/gitconfig` via `programs.git`: `gpg.format = ssh`, `gpg.ssh.program = <pets>`, `user.signingkey = key::<signingKey>`, `commit.gpgsign`, `tag.gpgsign` |
| `git.signingKey` | `null` | required with `git.enable` |
| `git.allowedSigners` | `[ ]` | written to `/etc/petschaft/allowed_signers`, set as `gpg.ssh.allowedSignersFile` |
| `agent.enable` | `false` | systemd user service `petschaft-agent` (`pets agent`, see below) |

### SSH agent (NixOS)

`programs.petschaft.agent.enable = true;` adds the user service `petschaft-agent`:
`ExecStart = <pets> agent`, `Restart = on-failure`, `wantedBy = default.target` (started
for every user session). Socket: `$XDG_RUNTIME_DIR/petschaft/agent.sock`, its directory
is the unit's `RuntimeDirectory` (0700, removed when the service stops). Check it with
`systemctl --user status petschaft-agent` and `journalctl --user -u petschaft-agent`.
The config is read at start: `systemctl --user restart petschaft-agent` after a change.
Run `pets pair` once in a terminal before the first login (the service cannot ask for
a pairing code).

Hardening is deliberately conservative so USB (`/dev` is untouched), Bluetooth (BlueZ
on the system bus) and the Secret Service (session bus) keep working:
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem = strict` with
`ReadWritePaths = %t/petschaft`. No `PrivateDevices`, `ProtectHome`, `PrivateNetwork`,
address family or syscall filters (they would break USB HID, D-Bus or the Python
helper). In a user service, `PrivateTmp`/`ProtectSystem` need unprivileged user
namespaces; if your kernel disables them the service fails to start; then override
with `systemd.user.services.petschaft-agent.serviceConfig.PrivateTmp = lib.mkForce false;`
(and the same for `ProtectSystem`).

User (`~/.gitconfig`) and repository config still override the system gitconfig.

The THP pairing credential is stored in the Secret Service, so a provider must run in your
session (for example `services.gnome.gnome-keyring.enable = true` or KWallet). Without one,
`pets` does not store the credential and pairs again each time (there is no plaintext fallback).

### Bluetooth (Linux)

There are two pairings: the Bluetooth bond (operating system) and the THP pairing
(`pets pair`, code on the Trezor). The Trezor accepts only bonded, encrypted
connections, and creating the bond needs a BlueZ pairing agent (the Trezor expects
`DisplayYesNo`). macOS shows its own dialog; on Linux the helper has no agent, so create
the bond once before `pets pair`, with the Trezor in pairing mode:

```
$ bluetoothctl
[bluetooth]# agent KeyboardDisplay
[bluetooth]# default-agent
[bluetooth]# scan le          # wait for "Trezor Safe 7 (…)"
[bluetooth]# pair <address>   # confirm the code on both sides
[bluetooth]# trust <address>
[bluetooth]# scan off
[bluetooth]# disconnect <address>
```

A desktop Bluetooth dialog (GNOME, KDE, blueman) works too. Without a bond `pets` reports
"Bluetooth: the Trezor is not paired with this computer". The bond survives reboots
(`/var/lib/bluetooth`); remove it on both sides before pairing again.

BlueZ does not complete a connection to an LE device it does not see. trezorlib stops
scanning before it connects (with a 3 s timeout), so on Linux the helper keeps a scan
running until the connection is up and allows 30 s, as Trezor Suite does
(`packages/transport-bluetooth`, `scan_coordinator.rs`). A plain `bluetoothctl connect`
without a running scan hangs for the same reason; that says nothing about `pets`.

## nix-darwin

```nix
# flake.nix
outputs = { nix-darwin, petschaft, ... }: {
  darwinConfigurations.mac = nix-darwin.lib.darwinSystem {
    modules = [
      ./darwin.nix
      petschaft.darwinModules.default
    ];
  };
};
```

```nix
# darwin.nix
{
  programs.petschaft = {
    enable = true;
    settings = { /* same as above */ };
  };
}
```

The nix-darwin module has `enable`, `package`, `settings`, `agent.enable` and
`agent.logFile`:

| Option | Default | Effect |
|---|---|---|
| `agent.enable` | `false` | `launchd.user.agents.petschaft-agent` (`pets agent`; `RunAtLoad`, `KeepAlive`), started at login for every user; socket `~/Library/Application Support/petschaft/agent.sock` |
| `agent.logFile` | `null` | log file (stdout and stderr); `null`: `~/Library/Logs/petschaft-agent.log` of each user, appended via `/bin/sh` because launchd does not expand `~`, and rotated by that shell when the agent starts (> 1 MiB, 3 old files kept; no root `newsyslog` rule, which would operate as root in the user's directory and cannot make the running agent reopen the file). A configured `logFile` is not rotated. Never use a world-writable directory such as `/tmp` (launchd follows symlinks) |

Restart the agent after a config change:
`launchctl kickstart -k gui/$(id -u)/org.nixos.petschaft-agent`.

Git is not configured
system-wide on macOS: there is no single system gitconfig (Apple's `/usr/bin/git` reads
`/etc/gitconfig` plus the Xcode/Command Line Tools one, nixpkgs' git on Darwin reads only
the `etc/gitconfig` inside its store path). Run once per user:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program /run/current-system/sw/bin/pets
git config --global user.signingkey "key::$(pets pubkey git)"
git config --global commit.gpgsign true
```

USB and Bluetooth need no extra setup on macOS. The THP credential is stored in the login
Keychain.

## What is system-wide and what stays per user

The generated `/etc/petschaft/config.toml` and `/etc/petschaft/allowed_signers` contain only
public data: identity names, SLIP-0013 URIs, curves, public-key fingerprints, public keys
and APK signing certificates (`certificate`, from `pets apk init`).
They are world-readable in the Nix store, and it is fine to push the configuration that
produces them to a public repository.

`pets` reads `/etc/petschaft/config.toml` only when the user has no
`~/.config/petschaft/config.toml` (or `$XDG_CONFIG_HOME/petschaft/config.toml`); a user file
wins completely, the two are not merged.

Per user, never managed by Nix:

- FIDO2 key files under `~/.config/petschaft/fido2/` (key handle and `.pub`, created by
  `pets fido2 create`; they always live in the user's directory, also when the config comes
  from `/etc`),
- the THP pairing credential in the macOS Keychain or the Secret Service (Linux).

## Checks

`nix flake check` evaluates a minimal NixOS configuration (x86_64-linux) with the module
enabled, including the generated `/etc` entries, git config, udev packages, assertions, the
system's derivation path and the agent's systemd user unit (ExecStart, restart policy, runtime
directory, hardening; off by default). This is evaluation only, so it also runs on macOS
without building Linux derivations. The nix-darwin module is evaluated against stubs of
the nix-darwin options it uses (`environment.etc`, `environment.systemPackages` with
nix-darwin's types, `launchd.user.agents` loosely), with and without `agent.logFile`,
because nix-darwin is not an input of this flake.
