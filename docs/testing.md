# Testing

```bash
nix flake check            # everything: build, nextest, clippy, doctests, fmt, helper tests
nix develop -c cargo nextest run --workspace
nix develop -c pytest -q -p no:cacheprovider helper
```

Automated tests never talk to a real Trezor. Device paths are covered by a fake
helper device (`helper/fake_helper.py`) and software keys; FIDO2 tests that run the
real `ssh-keygen` always pass `-O device=/nonexistent/...` so an attached authenticator
is never asked to register a key. Tests never read `~/.ssh`, the real
`~/.config/petschaft` or `/etc/petschaft`: the config lookup (per-user file, then
`/etc/petschaft/config.toml`) is tested through `locate_in` with paths in a temporary
directory.

APK tests (`petschaft-apk`, `pets apk` in `crates/petschaft/src/apk/tests.rs`) run
Google's `apksigner` on every APK they sign: `PETSCHAFT_APKSIGNER` (the EC-capable
apksigner from `nix/package.nix`) is set by the dev shell and the Nix build, and the
tests fail without it. The `pets apk` tests also run Google's `aapt2`
(`PETSCHAFT_AAPT2`, set the same way) on test APKs with a hand-written binary manifest;
they fail without it, except in builds marked `PETSCHAFT_NO_AAPT2` (aarch64-linux, where
nixpkgs has no aapt2), which skip the tests needing it. `PETSCHAFT_OPENSSL` (also set
there) enables an extra `openssl x509` check of the certificate. The `pets apk` tests use a fake device that signs like
the firmware does for gpg/nist256p1 and goes through `SignedIdentity::from_device`.

## Test keys

Tests use throw-away keys generated from **public, fixed seeds**. They exist only for
tests, are not secret and must never be trusted anywhere (never put them into an
`authorized_keys`, `allowed_signers` or a petschaft config you use).

| Purpose | Seed (Ed25519) | OpenSSH fingerprint |
|---|---|---|
| config fixture `homelab` | `0x11` × 32 | `SHA256:2HS8bJpYBy7bDfWIQN304coFKT0s6CVPABFLYq+IX5E` |
| config fixture `git` | `0x22` × 32 | `SHA256:sijgBpZVy7erVIEPkg1iFzd6kBJm7+kWQS9wf+ge734` |

APK tests use P-256 keys from the seeds `0x11` × 32 (the test certificate `CN=petschaft
test`) and `0x22` × 32 (the "wrong device key"); config tests use `0x01 || seed × 31`.

Other tests derive keys from fixed seeds in the test code itself (e.g. `[7u8; 32]`).
Seeds in code are preferred over committed private key files: nothing looks like a
leaked credential to secret scanners, and the derivation is visible next to its use.

The `sk-*` public key lines in `crates/petschaft-fido2` are hand-built (fixed public
key bytes in the layout `ssh-keygen` writes); no authenticator or key handle exists
for them. `ssh-keygen -l` cross-checks their fingerprints.

## Fuzzing

`fuzz/` holds coverage-guided fuzz targets (cargo-fuzz / libFuzzer) for every parser of
untrusted bytes. It is its own cargo workspace (excluded from the main one, with its own
`fuzz/Cargo.lock`) and is not built by `nix flake check`. Its only extra dependency is
`libfuzzer-sys` (which brings `arbitrary` transitively); the crates are used by path.

| Target | Under test | Invariants besides "never panics" |
|---|---|---|
| `helper_frame` | `read_frame` on a stream, each payload through `decode_host_message` / `decode_helper_message` | frame and message round-trip |
| `helper_message` | `decode_host_message`, `decode_helper_message` | decode → encode → decode is the identity, encoding stable |
| `core_config` | `Config::from_toml_str` | deterministic |
| `core_identity` | `Identity::parse` (4-byte index, then URI) | `parse(to_uri())` round-trip |
| `core_device_key` | `PublicKey::from_device` + `verify_identity_signature` | OpenSSH blob/line round-trip; **no fuzzer-made signature verifies** |
| `core_openssh_key` | `PublicKey::from_openssh_line`, `PublicKey::from_openssh_blob` | accepted blob is canonical; line, blob and fingerprint round-trip |
| `core_fingerprint` | `Fingerprint::parse` | exact (text kept byte for byte) |
| `sshsig_keyline` | `petschaft_sshsig::KeyLine::parse` | only the two algorithms; blob starts with its algorithm |
| `fido2_pubkey_line` | `petschaft_fido2::PublicKeyLine::parse` | `parse(to_line())` round-trip |
| `agent_session` | `read_message` stream → `parse_request` → `parse_userauth` → `authorize` | framing round-trip; an `Ok` from `authorize` satisfies every signing rule; no binding or no pin is always denied |
| `agent_userauth` | `parse_userauth` | SSHSIG data is never a userauth; field bounds |
| `apk_parse` | `petschaft_apk::Apk::parse`, then `is_aligned`, `content_digest`, `remove_signing_block`, `align` | a present signing block always blocks the digest; `align` reaches a fixed point (aligned afterwards, idempotent digest) |

Verification is never switched off for fuzzing (see `CONTRIBUTING.md`): the targets call
the parsers below the verifiers directly. The seeds in `fuzz/corpus/<target>/seed-*` are
small and committed (the agent seeds are the OpenSSH captures from
`crates/petschaft-agent/src/test_vectors.rs`, so `authorize` is reached with real
session-binds; the `apk_parse` seeds are unsigned and v2+v3 / v3-signed APKs from the
`crates/petschaft-apk/tests/common` builders); everything libFuzzer adds to the corpus, `fuzz/artifacts` and
`fuzz/target` are ignored by git.

Toolchain: no nightly. The flake's stable rustc is told to accept the `-Z` flags
cargo-fuzz passes with `RUSTC_BOOTSTRAP=1` (development only, never for release
builds), and `--sanitizer none` is used because the petschaft crates forbid `unsafe`
(ASan would need a nightly-only runtime). cargo-fuzz comes from the dev shell.

```bash
cd fuzz
nix develop .. -c env RUSTC_BOOTSTRAP=1 cargo fuzz list
nix develop .. -c env RUSTC_BOOTSTRAP=1 cargo fuzz build --sanitizer none
# one target, 60 s:
nix develop .. -c env RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none agent_session -- -max_total_time=60
# reproduce / minimize a crash:
nix develop .. -c env RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none agent_session artifacts/agent_session/crash-<hash>
nix develop .. -c env RUSTC_BOOTSTRAP=1 cargo fuzz tmin --sanitizer none agent_session artifacts/agent_session/crash-<hash>
# all targets, 60 s each:
for t in $(nix develop .. -c cargo fuzz list); do
  nix develop .. -c env RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none "$t" -- -max_total_time=60
done
```

`fuzz_target!` expands to `#[unsafe(no_mangle)]`, so the fuzz crate itself cannot carry
`forbid(unsafe_code)`; the crates under test keep theirs.
