# Contributing

petschaft signs SSH logins, git commits and APKs. A bug here can cost server access or
the ability to ship app updates, so changes are held to the rules below.

## Workflow

- Use the flake for everything (`nix develop -c cargo nextest run --workspace`,
  `nix develop -c cargo clippy --workspace --all-targets -- -D warnings`,
  `nix develop -c cargo fmt`, `nix develop -c pytest helper`, `nix develop -c ruff check helper`).
- `nix flake check` is the gate: a change is not done before it passes. New files must
  be `git add`-ed, otherwise Nix does not see them.
- Release binaries come only from `nix build` (fixed store paths for the helper). A
  `cargo build` inside `nix develop` bakes in the mutable worktree path of the helper
  script and is for development only.
- Tests never talk to a real Trezor or authenticator: use the fake helper device and
  software keys, and pass `-O device=/nonexistent/...` to any FIDO2 `ssh-keygen` call
  (see [docs/testing.md](docs/testing.md)).

## Rules

1. Every crate has `#![forbid(unsafe_code)]`. If something seems to need `unsafe`,
   open an issue first.
2. Code that handles untrusted bytes has no `unwrap`/`expect`/`panic!` and no indexing
   without a length check; arithmetic on lengths and offsets uses `checked_*`.
3. Fail closed. Every signature from the device is verified locally against the public
   key before it is used; a pinned fingerprint that does not match aborts. There is no
   option to turn this off.
4. Verification (signature, digest, MAC, fingerprint) never depends on `cfg(fuzzing)`,
   `cfg(test)` or feature flags. Fuzz targets call the parsers below the verifiers
   directly.
5. Secrets (the THP pairing credential) are handled only by the Rust code and stored
   only in the macOS Keychain or the Secret Service. Without a secure store nothing is
   stored (no plaintext fallback). Secrets never appear in logs, error messages or
   debug output.
6. The Python helper stays minimal: only the operations in
   [docs/helper-protocol.md](docs/helper-protocol.md), strict validation, no files, no
   network, no dependencies besides trezorlib.
7. Every parser of untrusted bytes gets property tests (proptest) and a fuzz target.
   Protocol code is checked against its specification.
8. New dependencies need a reason; prefer RustCrypto and std, no pre-release crates.
9. File and socket permissions: secrets 0600, socket directory 0700; the config must not
   be group- or other-writable.
10. Style: English for code, comments and commit messages. No em dashes or spaced en
    dashes in text or comments; use a comma, colon, parentheses or a plain hyphen
    (ranges as `1-32`).

## Reporting security issues

See [SECURITY.md](SECURITY.md); please do not open public issues for vulnerabilities.
