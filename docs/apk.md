# `pets apk`: APK signing design

Signs Android APKs with an ECDSA P-256 key on the Trezor (APK Signature Scheme v2 and
v3, algorithm `0x0201` ECDSA with SHA2-256). Private key on the device; every APK is
confirmed on the display, which shows the app's package name and version
(`org.example.app:1.4.2(42)`, read from the manifest with Google's `aapt2`); every output
is verified by Google's `apksigner` before it is written.

**Only for apps with `minSdkVersion` ≥ 24 (Android 7.0).** Every APK gets a v2 and a v3
signature, as apksigner does by default for minSdkVersion 24-27; there are no v1 (JAR)
signatures, which Android < 7.0 needs. `pets apk sign` reads the minSdkVersion from the
manifest and refuses apps below 24 (and apps whose manifest has no numeric
minSdkVersion).

## Identity

```toml
[[identity]]
name = "apk-release"
uri = "gpg://apk@release"     # gpg proto: the device signs a 32-byte digest as given
curve = "nist256p1"
passphrase = "ask"            # recommended: a strong passphrase for release keys
                              #   (needs passphrase protection enabled on the Trezor)
fingerprint = "SHA256:…"
certificate = "MIIB…"         # base64 DER, written by `pets apk init`, public data
```

Android identifies the signer by the **certificate**, not only the key, so the exact
certificate bytes must be kept forever (app updates fail otherwise). It is public and
lives in the config (and therefore in the NixOS config repository).

The config validates `certificate` at load: only on `gpg://` identities with curve
`nist256p1`; it must be exactly a certificate `pets apk init` builds (canonical encoding,
valid self-signature); if the identity is pinned (`fingerprint` or `public_key`), the
certificate's key must be the pinned key. `pets apk sign` additionally requires the pin.

## Play App Signing and other stores

The key can serve two roles:

- **App signing key** for sideloading, F-Droid (reproducible builds with the developer's
  signature), Obtainium and other stores that install the APK as you signed it. Then the
  certificate SHA-256 printed by `pets apk init` / `sign` is the "signing certificate
  digest" users and stores pin.
- **Upload key** for Google Play with Play App Signing: Google keeps the app signing key
  and re-signs what you upload; the petschaft key only authenticates the upload. Check in
  the Play Console documentation which upload key types and formats Play accepts before
  relying on it (not verified here: whether an EC P-256 upload certificate is accepted).
  New Play apps are uploaded as AABs, which `pets` does not sign (see "Out of scope"), so
  this role only fits apps that still upload APKs.

## Commands

- `pets apk init <name> --subject "CN=…"` (or a bare CN; 1-64 printable ASCII, one
  attribute): two confirmations: (1) `apk init <name>`, a random 32-byte challenge that
  yields the device public key (verified against the signature and the pin, if any);
  (2) `apk cert <CN>`, SHA-256 of the TBSCertificate. The certificate is self-signed
  X.509 v3 for the identity's P-256 key (serial = first 16 bytes of SHA-256 of the public
  key, validity 2026-01-01 to 2126-01-01, `ecdsa-with-SHA256`); the signature is verified
  before anything is printed. Prints the `certificate = "…"` config line (plus
  `fingerprint = "…"` if the identity is not pinned yet) on stdout and the certificate
  SHA-256 in the Play Console's form (`AB:CD:…`) on stderr. Refused if the identity
  already has a `certificate`.
- `pets apk sign <name> <in.apk> -o <out.apk> [--replace]`: see below. Two
  confirmations (v2, then v3), each showing `apk <v2|v3> <package>:<versionName>(<versionCode>)
  <first 8 hex of the content digest>`. `-o` must not exist, and its directory must be
  on a file system with hard links (see step 7). The final summary repeats
  `package:versionName(versionCode)` and the minSdkVersion.
- `pets apk verify <apk> [--min-sdk N]`: runs `apksigner verify -v --print-certs
  [--min-sdk-version N] <apk>` (baked path; a relative path is passed as `./<apk>`, so a
  name starting with `-` is never an option); no config, no device, no `--config`.
  Without `--min-sdk`, apksigner reads the minSdkVersion from the APK's manifest.

`--config <file>` goes after the subcommand (`pets apk sign --config <file> …`).

```bash
pets apk init apk-release --subject "CN=Example Release"   # add the printed line(s)
pets apk sign apk-release app-release-unsigned.apk -o app-release.apk
pets apk verify app-release.apk
```

## Signing pipeline

0. Before the device is asked: identity is `gpg://` nist256p1 with `certificate` and a
   pin, `-o` does not exist, the baked `apksigner` and `aapt2` paths resolve to
   executable regular files (symlinks followed).
1. Read the input (size limit **256 MiB**: input, re-laid-out copy and output are held
   in memory together, so signing needs about three times the APK size), parse the ZIP
   end-of-central-directory, central directory and local headers strictly (no ZIP64, no
   multi-disk, no data descriptors with ambiguous sizes, no existing APK Signing Block
   unless `--replace`, then it is removed). Every offset/length with checked
   arithmetic. Input with v1 signature files of a previous signer (`META-INF/*.SF`,
   `*.RSA`, `*.DSA`, `*.EC`, ASCII case-insensitive) is refused, with or without
   `--replace`: `pets` does not remove them, and they would stay next to the new
   signatures. Sign the unsigned build output instead. (A `META-INF/MANIFEST.MF` with
   per-entry digests alone is not detected; without a signature file it carries no
   signature.)
1a. Read the manifest: `aapt2 dump badging <in.apk>` (see "aapt2" below) yields the
   package name, versionCode, versionName and minSdkVersion. Any of them missing or
   invalid, or minSdkVersion < 24: refused, nothing is signed.
2. Align: uncompressed entries to 4 bytes, uncompressed `.so` to 16 KiB (Android page
   alignment), by padding the local header's extra field; rebuild the central directory.
3. Content digest (v2/v3, chunked SHA-256): 1 MiB chunks of (a) ZIP entries, (b) central
   directory, (c) EOCD with its central-directory-offset field set to the offset of the
   signing block; top-level digest over `0x5a || chunk count || chunk digests`.
4. Build `signed data` for v2 and v3: digests, certificate, additional attributes (v2:
   the stripping-protection attribute for v3), and for v3 minSDK 28 / maxSDK
   `0x7fffffff` (Android 7.0-8.1 use v2, Android 9 and later v3).
5. Device signature: `SignIdentity` with the `gpg://` identity, `challenge_hidden =
   SHA-256(signed data)`, `challenge_visual = "apk <v2|v3>
   <package>:<versionName>(<versionCode>) <first 8 hex of content digest>"`, e.g.
   `apk v2 org.example.app:1.4.2(42) 3f2a9c01` (at most 128 characters, display-safe;
   versionName display-safe and truncated to 32 characters, a package name too long for
   the rest is truncated with `…`). Two confirmations, v2 then v3; right before each,
   the same text is printed on the terminal so it can be compared with the display. The answer is verified (signature,
   pin) by `SignedIdentity::from_device`; its key must equal the certificate's key, and
   `petschaft_apk::sign` verifies the DER signature against the certificate again.
6. Assemble the APK Signing Block (`0x7109871a` v2, `0xf05368c0` v3, size fields, magic
   `APK Sig Block 42`), insert it before the central directory, fix the EOCD offset.
7. Write the result to a temporary file next to `-o`, run `apksigner verify -v
   --min-sdk-version <the app's minSdkVersion> --print-certs` on it (it must succeed,
   report v3 (and for minSdkVersion < 28 also v2; from 28 on apksigner, like Android,
   checks only v3, and `petschaft_apk::sign` has verified the v2 signature itself) as
   verified, and show exactly our certificate digest as signer #1), then a plain
   `apksigner verify` (apksigner reads the minSdkVersion from the manifest with its own
   parser, an independent check of aapt2's answer), then hard-link it to `-o` (fails
   instead of replacing a file that appeared meanwhile) and remove the temporary name.
   Print the app, the certificate digest and the schemes. **The directory of `-o`
   must support hard links:** on exFAT, FAT or some SMB/network shares the link fails
   (only after both confirmations) and nothing is written (fail closed); sign into a
   local directory and copy the result.

## apksigner

nixpkgs' `apksigner` runs on a minimal JRE without `jdk.crypto.ec` and fails on EC keys
("EC KeyFactory not available"). `nix/package.nix` wraps the same apksigner jar with a
minimal JRE that adds `jdk.crypto.ec` (passthru `apksigner`) and bakes its
`bin/apksigner` into the binary as `PETSCHAFT_APKSIGNER` (compile time wins over the
environment variable of the same name, which only matters for dev builds without a baked
path; absolute paths only). The dev shell sets it, too. apksigner runs without the
variables that change the JVM or the wrapper (`JAVA_OPTS`, `APKSIGNER_OPTS`,
`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`). The checks
of `pets apk sign` run it with stdin from `/dev/null`, at most 1 MiB of stdout (64 KiB of
stderr) and a 120 s deadline per run (JVM start plus hashing up to 256 MiB); more output
or a timeout kills it and nothing is written.

## aapt2

`pets apk sign` runs Google's `aapt2 dump badging` (nixpkgs `aapt`) on the input APK,
baked in as `PETSCHAFT_AAPT2` with the same rules as apksigner (compile time wins,
absolute path, executable check before the device is asked). It runs with an **empty
environment**, stdin from `/dev/null`, at most 1 MiB of stdout (64 KiB of stderr) and a
30 s deadline; more output or a timeout kills it and signing is refused.

`dump badging` (not `dump xmltree`) because it reports what Android uses: it resolves
resource references (a versionName from `@string/…`) and applies the manifest's
defaults; it needs no `resources.arsc` but refuses a corrupt one. Its output is parsed
strictly, because aapt2 prints manifest strings **without escaping**:

- the first line must be the only `package:` line and exactly
  `package: name='<p>' versionCode='<n>' versionName='<v>'`, optionally followed by
  ` key='value'` pairs (`platformBuildVersionName`, `compileSdkVersion`, … as AGP adds);
  a versionName containing `'` therefore cannot be read and is refused;
- package name: `.`-separated segments `[A-Za-z][A-Za-z0-9_]*`, at least two, at most
  128 characters; versionCode: decimal `u32`; versionName: non-empty, shown
  display-safe and truncated to 32 characters;
- exactly one `minSdkVersion:'<n>'` (or `sdkVersion:'<n>'`) line, decimal (a preview
  codename is refused).

A versionName with a newline could fake the minSdkVersion line of an app without
`<uses-sdk>`; the plain `apksigner verify` of step 7 reads the manifest itself and
rejects such an APK (tested).

aapt2 reads a private temporary copy (mode 0600, removed afterwards) of exactly the bytes
`pets` signs, so the package name and version shown on the device belong to the signed
input even if the file is replaced while signing.

**Platforms:** nixpkgs has `aapt` for x86_64-linux, aarch64-darwin and x86_64-darwin
(Google ships no aarch64-linux aapt2). On aarch64-linux the package builds without a
baked aapt2 (`PETSCHAFT_NO_AAPT2`, the tests needing aapt2 are skipped there) and `pets
apk sign` fails with "PETSCHAFT_AAPT2 is not set" unless `PETSCHAFT_AAPT2` is set at run
time to an aapt2 you trust; `pets apk init` and `pets apk verify` work.

## Testing

Format code is device-independent: tests use a software P-256 key through the same
`SignedIdentity` verification path and check every produced APK with the real
`apksigner` (in the Nix build's check inputs; the tests fail, not skip, without
`PETSCHAFT_APKSIGNER`). `pets apk init` / `sign` are tested end to end with a fake
device in `crates/petschaft/src/apk/tests.rs`, including the fail-closed cases (wrong
device key, missing certificate or pin, existing output, output appearing during
signing, apksigner or aapt2 missing or not executable, v1 signature files, input over
the size limit). Their APKs carry a binary `AndroidManifest.xml` written by hand in the
test code (string pool, resource map with the android attribute ids, `<manifest>` and
`<uses-sdk>` elements; no Android SDK needed) that the real `aapt2` reads
(`PETSCHAFT_AAPT2`; required like apksigner, except in builds marked
`PETSCHAFT_NO_AAPT2`): minSdkVersion 24 and 30 sign, 21/23 and a missing `<uses-sdk>`,
manifest, package name or versionName are refused, and a versionName faking the
minSdkVersion line is caught by apksigner. Fake aapt2 scripts cover endless output,
endless stderr, a hanging aapt2, failures and the empty environment; the badging
parser has unit and property tests. Property tests for the ZIP parser and certificate, fuzz
target `apk_parse` (`docs/testing.md`). Not tested here: a real Trezor (the gpg/nist256p1
signature format is the one `SignIdentity` returns for `pets pubkey`), installing the
APK on a device, Play Console acceptance of the certificate.

## Out of scope (for now)

v1 (JAR) signatures (apps with minSdkVersion < 24 are refused), v3.1 key rotation, v4
incremental signatures, AAB/bundles.
