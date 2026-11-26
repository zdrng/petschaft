# The petschaft package (CLI `pets`). Used by the flake's packages, by
# overlays.default and as the modules' fallback package, so it may be built
# against a consumer's nixpkgs: the trezorlib assertion below guards that.
{
  lib,
  stdenv,
  rustPlatform,
  python3,
  openssh,
  openssl,
  writeText,
  apksigner,
  aapt,
  jre_minimal,
  makeWrapper,
  runCommand,
}:

let
  # The helper speaks THP through trezorlib's internal API, which changes
  # between minor releases. Refuse to build against an untested trezorlib.
  trezorVersion = python3.pkgs.trezor.version;
  trezorSupported =
    lib.versionAtLeast trezorVersion "0.20.2" && lib.versionOlder trezorVersion "0.21";

  # Python only for Trezor access (THP over USB and Bluetooth).
  # Deliberately minimal: trezorlib + cryptography, nothing else.
  helperPython = python3.withPackages (
    ps:
    [
      ps.trezor
      ps.cryptography
    ]
    ++ ps.trezor.optional-dependencies.ble
  );

  # The helper as its own immutable file in the Nix store.
  helperScript = writeText "petschaft_helper.py" (builtins.readFile ../helper/petschaft_helper.py);

  # Google's apksigner (verifies every APK `pets apk sign` writes, and runs
  # `pets apk verify`). nixpkgs runs it on a minimal JRE without jdk.crypto.ec, so
  # it cannot read EC keys ("EC KeyFactory not available"). Same jar, same module
  # list plus jdk.crypto.ec; no rebuild of apksigner itself.
  apksignerJre = jre_minimal.override {
    modules = [
      "java.base"
      "java.compiler"
      "java.logging"
      "java.naming"
      "java.security.jgss"
      "java.sql"
      "jdk.unsupported"
      "jdk.crypto.ec"
    ];
  };
  apksignerEc =
    runCommand "apksigner-ec-${apksigner.version}"
      {
        nativeBuildInputs = [ makeWrapper ];
        meta.mainProgram = "apksigner";
      }
      ''
        makeWrapper ${apksigner}/opt/apksigner/bin/apksigner $out/bin/apksigner \
          --set JAVA_HOME ${apksignerJre.home}
      '';

  # Google's aapt2 (`aapt2 dump badging`: package name, version and minSdkVersion that
  # `pets apk sign` shows and checks). Google ships no aarch64-linux build, so nixpkgs
  # has none: there petschaft builds without it and `pets apk sign` refuses to run
  # (unless PETSCHAFT_AAPT2 is set at run time); its tests needing aapt2 are skipped.
  aapt2 = if lib.meta.availableOn stdenv.hostPlatform aapt then "${aapt}/bin/aapt2" else null;
in

assert lib.assertMsg trezorSupported ''
  petschaft: the helper is written for trezorlib >= 0.20.2 and < 0.21,
  but this nixpkgs provides python3.pkgs.trezor ${trezorVersion}.
  Let petschaft use its own pinned nixpkgs (drop the
  `inputs.petschaft.inputs.nixpkgs.follows` line) or use a nixpkgs release
  with a supported trezorlib.
'';

rustPlatform.buildRustPackage {
  pname = "petschaft";
  inherit ((lib.importTOML ../Cargo.toml).workspace.package) version;

  # Only what the Rust build needs; helper/ for the end-to-end test against the
  # real helper (crates/petschaft-device/tests/e2e_helper.rs).
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../helper
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;

  # No system libraries: on Linux the Secret Service is reached through zbus
  # (pure Rust, no libdbus), so neither pkg-config nor dbus is needed.

  # Fixed store paths: the release binary uses exactly this helper and exactly
  # this OpenSSH (with libfido2 for sk keys; the one shipped with macOS has no
  # FIDO2). Embedding the store paths makes both runtime dependencies.
  env = {
    PETSCHAFT_HELPER_PYTHON = "${helperPython}/bin/python3";
    PETSCHAFT_HELPER_SCRIPT = "${helperScript}";
    PETSCHAFT_OPENSSH_BIN = "${openssh}/bin";
    # Also read at run time by the petschaft-apk tests (they fail without it).
    PETSCHAFT_APKSIGNER = "${apksignerEc}/bin/apksigner";
    # Optional certificate check in the petschaft-apk tests (skipped when unset).
    PETSCHAFT_OPENSSL = "${lib.getBin openssl}/bin/openssl";
  }
  // (
    if aapt2 != null then
      {
        # Also read at run time by the `pets apk` tests (they fail without it).
        PETSCHAFT_AAPT2 = aapt2;
      }
    else
      {
        # Marks the build without aapt2: the `pets apk` tests needing it are skipped.
        PETSCHAFT_NO_AAPT2 = "1";
      }
  );

  useNextest = true;
  # petschaft-sshsig tests verify our signatures with the real ssh-keygen;
  # petschaft-fido2 tests run the baked PETSCHAFT_OPENSSH_BIN; petschaft-apk and
  # `pets apk` tests run PETSCHAFT_APKSIGNER on every APK they sign, `pets apk` tests
  # PETSCHAFT_AAPT2 on their test APKs.
  nativeCheckInputs = [
    openssh
    apksignerEc
  ]
  ++ lib.optional (aapt2 != null) aapt;

  passthru = {
    inherit helperPython helperScript aapt2;
    apksigner = apksignerEc;
  };

  meta = {
    description = "SSH login, git and APK signing with a Trezor Safe 7";
    license = lib.licenses.gpl3Plus;
    mainProgram = "pets";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
