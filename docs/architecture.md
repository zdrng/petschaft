# petschaft architecture

```
ssh ──────────────SSH agent protocol──▶ pets agent ─┐        (docs/agent.md)
git (gpg.ssh.program) ─────────────────▶ pets ───────┤
pets apk init / sign ───────────────────▶ pets ───────┤        (docs/apk.md)
pets pubkey / list / forget ─────────────▶ pets ───────┤
                                                      ▼
                                   petschaft-device: trait Signer
                                   HelperSigner ── stdin/stdout frames ──▶ python3 -I petschaft_helper.py
                                                                            (trezorlib, THP, USB/BLE)
```

## Crates

| Crate | Responsibility | Knows the device? |
|---|---|---|
| `petschaft-core` | Identities (SLIP-0013 URIs and paths), curves, config schema and parsing (identity kinds slip13/fido2), public keys (OpenSSH encoding, fingerprints), verification of device signatures | no |
| `petschaft-helper-proto` | Frame codec and message types of `docs/helper-protocol.md` | no |
| `petschaft-device` | `Signer` trait; `HelperSigner` (spawns and drives the helper, enforces timeouts); credential storage (keychain / Secret Service); verifies every signature and fingerprint pin before returning | yes |
| `petschaft` | CLI binary | via `petschaft-device` |

`petschaft-sshsig` builds git (SSHSIG) signatures. `petschaft-agent` is the ssh-agent
protocol and signing policy (pure); the daemon around it (`pets agent`: socket, threads,
device worker) is in `petschaft`. `petschaft-apk` is the APK v2/v3 and X.509 format code
(pure; `petschaft-core` uses it to validate the `certificate` config key); `pets apk` in
`petschaft` drives the device, `aapt2` and `apksigner`.
Format crates (`petschaft-sshsig`, `petschaft-apk`) never touch the device, so they are tested with
a software signer.

## Baked tool paths

External programs are fixed at build time: `nix build` bakes Nix store paths into the
binary, so a release `pets` never looks anything up in `PATH`. All are absolute paths;
an empty value counts as unset.

| Variable | Used for |
|---|---|
| `PETSCHAFT_HELPER_PYTHON` | the Python interpreter (with trezorlib) that runs the helper (`python3 -I`) |
| `PETSCHAFT_HELPER_SCRIPT` | the helper script `petschaft_helper.py` |
| `PETSCHAFT_OPENSSH_BIN` | directory of the FIDO2-capable `ssh` / `ssh-keygen` (fido2 identities) |
| `PETSCHAFT_APKSIGNER` | the EC-capable `apksigner` that verifies every signed APK (`docs/apk.md`) |
| `PETSCHAFT_AAPT2` | Google's `aapt2`, reads package name, version and minSdkVersion of an APK to sign (`docs/apk.md`; none on aarch64-linux) |

The compile-time value always wins. The environment variable of the same name at run
time is only a fallback for development builds compiled without it; it cannot redirect
a release binary. A `cargo build` inside `nix develop` bakes the dev shell's values,
including the mutable worktree path `helper/petschaft_helper.py`, for development only;
release binaries come from `nix build`.

## Invariants

- The private keys never leave the Trezor; petschaft holds no key material.
- Every signature returned by `petschaft-device` has been verified locally against the
  public key returned with it, and against the pinned fingerprint if the identity has one.
- The THP pairing credential is stored only in the OS secret store; without one,
  nothing is stored. The helper receives it per process via stdin.
- Per-identity passphrase policy (slip13): `ask` (new session, passphrase on device,
  every signature) or `standard` (standard wallet, no prompt). Default: `ask`, which
  needs passphrase protection enabled on the Trezor (off on a factory device; otherwise
  every signature fails with a hint to set `passphrase = "standard"`).
- FIDO2 identities never reach `petschaft-device` (enforced by the types, see
  "Parse, don't validate").

## Configuration

Lookup order (first match wins; files are never merged):

1. `--config <file>`, if given (an option of each subcommand that reads the config, e.g.
   `pets list --config <file>`; `pets forget` and `pets apk verify` read none and do not
   accept it);
2. the per-user file `$XDG_CONFIG_HOME/petschaft/config.toml`, default
   `~/.config/petschaft/config.toml` (macOS and Linux), if anything exists at that path
   (a broken per-user file (e.g. a dangling symlink) is an error, not a reason to fall back);
3. the system file `/etc/petschaft/config.toml` (`petschaft_core::config::SYSTEM_CONFIG_PATH`),
   written by the NixOS / nix-darwin module: root-owned, usually a symlink chain into
   `/nix/store`.

Neither 2 nor 3 present → error naming both paths. Symlinks are followed; the final
file must be a regular file owned by the current user or root and not writable by
group/others. The directory holding it (after following symlinks) must also be owned
by the current user or root and not be group/other-writable, unless it is sticky
(`/nix/store`: root-owned, mode 1775, so the module's read-only root-owned file is
accepted). The current uid is the owner of a socket pair `pets` creates (std has no
`getuid`, and `unsafe` is forbidden); no file is created for it.

FIDO2 key handles always live in the per-user directory
`$XDG_CONFIG_HOME/petschaft/fido2/` (`~/.config/petschaft/fido2/`), independent of
which config file was loaded (also with `--config` or the system config): they belong
to the user running `pets`, never next to a shared config.

```toml
transport = "auto"            # auto | usb | ble; slip13 identities only
owner = "user"                # optional; 1-32 chars of [a-z0-9_-], not starting with "-"

[defaults]
passphrase = "ask"            # ask | standard; slip13 identities only

[[identity]]
name = "git"                  # [a-z0-9-], 1-32 chars, unique across all kinds
kind = "slip13"               # optional, default slip13
uri = "ssh://user@git-signing" # SLIP-0013 identity; proto ssh or gpg
curve = "ed25519"             # ed25519 | nist256p1
index = 0                     # optional, default 0 (key rotation)
passphrase = "standard"       # optional, overrides [defaults]
fingerprint = "SHA256:…"      # optional pin; mismatch aborts
public_key = "ssh-ed25519 …"  # optional; OpenSSH key line of `curve` (from `pets pubkey`);
                              #   also the pin (must match `fingerprint` if both are set)
host_keys = ["SHA256:…"]      # optional; server host keys `pets agent` may log in to
                              #   (non-empty, unique, ≤ 64; needs public_key and ssh://)
certificate = "MIIB…"         # optional; APK signing certificate (base64 DER) from
                              #   `pets apk init`; only gpg:// + nist256p1, must match the pin
comment = "user git signing"  # optional (both kinds), see "Key comments"

[[identity]]
name = "homelab"
kind = "fido2"                # OpenSSH security key, used by OpenSSH over USB only
algorithm = "ed25519-sk"      # ed25519-sk | ecdsa-sk (required)
application = "ssh:homelab"   # optional, default ssh:<name>;
                              #   "ssh:" + 1-60 chars of [a-z0-9.-], unique among fido2 identities
user_verification = true      # optional, default true (-O verify-required: PIN on every use)
resident = false              # optional, default false (-O resident)
fingerprint = "SHA256:…"      # optional pin (set after the key is created)
```

### Key comments

Every key line petschaft prints (`pets pubkey` for both kinds, `pets fido2 create`,
the `authorized_keys` lines of `pets sshd-config`) carries the identity's effective
comment: `comment` if set, else `<owner>@hwkey:<name>` if `owner` is set, else
`hwkey:<name>`. For fido2 identities the configured comment replaces the one stored
in the `.pub` file, and it is the `-C` comment when the key is created.

`comment`: 1-128 characters, each a space, an ASCII graphic character or a letter/digit
of any script; no control characters (newline, escape), no format characters (bidi,
zero-width), no emoji or other non-ASCII symbols, no leading/trailing space.

The comment is metadata only: changing it never requires a new key, and nothing is
selected by it. git signing finds the identity by **fingerprint**: the key in git's
`user.signingkey` must equal the pinned `fingerprint` of exactly one slip13 identity
with an `ssh://` URI (and the Trezor must return that same key).

Identity kinds:

- **slip13** (default, so configs written before kinds existed load unchanged): the key
  is derived on the Trezor (SLIP-0013) and used through the petschaft helper over USB or
  Bluetooth (`transport`).
- **fido2**: an OpenSSH `sk-*` key. OpenSSH talks to the Trezor itself, over USB only;
  such an identity never goes through the helper, so it can never be used over Bluetooth.

Unknown keys are errors, and so are keys of the other kind (`uri`, `curve`, `index`,
`passphrase`, `public_key`, `host_keys`, `certificate`, `transport` in a fido2 identity; `algorithm`, `application`,
`user_verification`, `resident` in a slip13 one). `transport` and `owner` are never allowed
inside an identity. Error messages name the identity and the key, never a value.

### Parse, don't validate

The config is parsed once into types whose fields are private and whose only
constructors validate: `Name`, `Owner`, `Comment`, `Fingerprint`, `SkApplication`, `Identity` (parse),
`Slip13Identity` / `Fido2Identity` / `IdentityConfig` / `Config` (only from the config
parser), `PublicKey` (only `PublicKey::from_device`, the strict OpenSSH parsers
`from_openssh_blob` / `from_openssh_line`, or `from_p256_uncompressed` for the key of an
APK certificate; always a fully validated point) and
`Signature` (only `verify_identity_signature`). Holding a value is the proof that it was
checked, so no later code re-validates or can forget to. The same idea enforces the
kind rules: `petschaft_device::SignRequest::for_identity` takes a `&Slip13Identity`, which is
the only way to build a request, so a `Fido2Identity` cannot reach the helper or the
Bluetooth path at all (a type error, not a runtime check), and the request always
carries that identity's curve, passphrase policy and fingerprint pin.

## Further notes

- `pets agent` signs only strictly parsed SSH userauth requests (never `SSHSIG` data)
  and refuses forwarded connections, so a compromised server cannot obtain a git
  signature while the device shows a login (`docs/agent.md`).
- fido2 identities: `user_verification` and `resident` are fixed when the key is
  created (`pets fido2 create`); they live in the key handle, not in the `.pub` file,
  and petschaft cannot check them later. Do not change them in the config afterwards.
