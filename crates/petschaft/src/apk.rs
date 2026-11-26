//! `pets apk`: APK signing with a `gpg://` nist256p1 identity (`docs/apk.md`).
//!
//! The format code (ZIP, v2/v3 blocks, certificate) is `petschaft-apk`; this module adds
//! the device calls, the file handling, Google's `aapt2` to read the app's package name,
//! version and minSdkVersion from the binary manifest, and Google's `apksigner` as an
//! independent verifier of every APK before it is written.

use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use petschaft_apk::{Apk, Certificate, SchemeVersion, ecdsa_der_from_scalars};
use petschaft_core::{Curve, Proto, PublicKey, SignatureParts, Slip13Identity};
use petschaft_device::{SignRequest, SignedIdentity, Signer};

/// Largest input APK: signing holds the input, its re-laid-out copy and the output in
/// memory at the same time (about three times this at peak).
const MAX_APK: u64 = 256 * 1024 * 1024;
/// Lowest minSdkVersion `pets apk sign` accepts: v1 (JAR) signatures are not supported,
/// and Android < 7.0 (API 24) needs them.
const MIN_SDK: u32 = 24;
/// From this API level on, Android (and apksigner) verify only the v3 signature.
const V3_MIN_SDK: u32 = 28;
/// Longest versionName shown on the device and the terminal (longer ones are truncated).
const MAX_VERSION_NAME: usize = 32;
/// Longest Android package name accepted.
const MAX_PACKAGE_NAME: usize = 128;
/// Helper limit for `challenge_visual` (characters).
const MAX_VISUAL: usize = 128;
/// Most bytes of aapt2 or apksigner stdout read (stderr gets [`MAX_TOOL_STDERR`]).
const MAX_TOOL_STDOUT: usize = 1024 * 1024;
const MAX_TOOL_STDERR: usize = 64 * 1024;
/// How long aapt2 may run (it reads only the manifest and the resource table).
const AAPT2_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one `apksigner verify` may run: JVM start plus hashing an APK of up to
/// [`MAX_APK`] bytes, so longer than [`AAPT2_TIMEOUT`].
const APKSIGNER_TIMEOUT: Duration = Duration::from_secs(120);
/// Maximum CN length (RFC 5280 `ub-common-name`), as enforced by `Certificate::build`.
const MAX_CN_LEN: usize = 64;
/// Environment variable / compile-time setting with the `apksigner` binary.
const APKSIGNER_ENV: &str = "PETSCHAFT_APKSIGNER";
/// Environment variable / compile-time setting with the `aapt2` binary.
const AAPT2_ENV: &str = "PETSCHAFT_AAPT2";
/// Variables the JVM or the apksigner wrapper would read (options, agents, class path):
/// removed from apksigner's environment so the verifier cannot be altered from outside.
const JVM_ENV: [&str; 6] = [
    "JAVA_OPTS",
    "APKSIGNER_OPTS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
];

/// The baked `apksigner`: compile-time `PETSCHAFT_APKSIGNER` (the fixed Nix store path of
/// release builds) wins over the runtime variable; it must be an absolute path.
pub(crate) fn apksigner_path() -> Result<PathBuf> {
    resolve_tool(
        APKSIGNER_ENV,
        option_env!("PETSCHAFT_APKSIGNER"),
        std::env::var_os(APKSIGNER_ENV),
        "",
    )
}

/// The baked `aapt2`, with the same rules as [`apksigner_path`]. nixpkgs has no aapt2
/// for aarch64-linux, so builds there have none baked in.
pub(crate) fn aapt2_path() -> Result<PathBuf> {
    resolve_tool(
        AAPT2_ENV,
        option_env!("PETSCHAFT_AAPT2"),
        std::env::var_os(AAPT2_ENV),
        " (nixpkgs has no aapt2 for aarch64-linux: there, set it at run time to an aapt2 \
         you trust, or sign on another platform)",
    )
}

fn resolve_tool(
    env: &str,
    compile_time: Option<&str>,
    runtime: Option<OsString>,
    hint: &str,
) -> Result<PathBuf> {
    let chosen = match compile_time.filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => match runtime.filter(|s| !s.is_empty()) {
            Some(s) => PathBuf::from(s),
            None => bail!(
                "{env} is not set (neither at build time nor in the environment); use the \
                 Nix build of petschaft, which bakes it in{hint}"
            ),
        },
    };
    if !chosen.is_absolute() {
        bail!("{env} must be an absolute path");
    }
    Ok(chosen)
}

/// A tool must be an executable regular file (symlinks followed), checked before the
/// device is asked so no confirmation is wasted.
fn check_tool(name: &str, path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("{name} {}", path.display()))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        bail!("{name} {} is not an executable file", path.display());
    }
    Ok(())
}

fn check_apksigner(apksigner: &Path) -> Result<()> {
    check_tool("apksigner", apksigner)
}

/// The app as its manifest describes it (read by `aapt2 dump badging`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppInfo {
    /// Android package name (validated).
    pub package: String,
    pub version_code: u32,
    /// Display-safe, at most [`MAX_VERSION_NAME`] characters.
    pub version_name: String,
    pub min_sdk: u32,
}

/// `org.example.app:1.4.2(42)`.
impl fmt::Display for AppInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}({})",
            self.package, self.version_name, self.version_code
        )
    }
}

/// An Android package name: at least two `.`-separated segments of
/// `[A-Za-z][A-Za-z0-9_]*`, at most [`MAX_PACKAGE_NAME`] characters.
fn valid_package_name(name: &str) -> bool {
    name.len() <= MAX_PACKAGE_NAME
        && name.split('.').count() >= 2
        && name.split('.').all(|seg| {
            let mut bytes = seg.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
                && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// A decimal `u32` (ASCII digits only, no sign, no whitespace).
fn decimal_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parses `aapt2 dump badging` output. aapt2 prints manifest strings without escaping,
/// so the parse is strict: the first line must be exactly
/// `package: name='<package>' versionCode='<n>' versionName='<name>'` followed only by
/// further ` key='value'` pairs (platformBuildVersionName, compileSdkVersion, ...), it
/// must be the only `package:` line, and exactly one `minSdkVersion:'<n>'` (or
/// `sdkVersion:'<n>'`) line must exist.
fn parse_badging(text: &str) -> Result<AppInfo> {
    let malformed = || anyhow!("aapt2 printed no well-formed \"package:\" line first");
    if text.lines().filter(|l| l.starts_with("package:")).count() != 1 {
        bail!("aapt2 printed no or several \"package:\" lines");
    }
    let first = text.lines().next().ok_or_else(malformed)?;
    let rest = first
        .strip_prefix("package: name='")
        .ok_or_else(malformed)?;
    let (package, rest) = rest.split_once("' versionCode='").ok_or_else(malformed)?;
    let (code, rest) = rest.split_once("' versionName='").ok_or_else(malformed)?;
    let (name, mut extra) = rest.split_once('\'').ok_or_else(malformed)?;
    while !extra.is_empty() {
        let (key, value_rest) = extra
            .strip_prefix(' ')
            .and_then(|e| e.split_once("='"))
            .ok_or_else(|| {
                anyhow!(
                    "aapt2 printed an unexpected \"package:\" line (a quote in the versionName?)"
                )
            })?;
        let (_value, next) = value_rest.split_once('\'').ok_or_else(malformed)?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            bail!("aapt2 printed an unexpected \"package:\" line (a quote in the versionName?)");
        }
        extra = next;
    }
    if !valid_package_name(package) {
        bail!(
            "the manifest's package name {:?} is not a valid Android package name",
            crate::git::truncate_chars(&crate::git::display_safe(package), 80)
        );
    }
    let version_code = decimal_u32(code).ok_or_else(|| {
        anyhow!(
            "the manifest has no valid versionCode (aapt2 shows {:?})",
            crate::git::truncate_chars(&crate::git::display_safe(code), 40)
        )
    })?;
    if name.is_empty() {
        bail!("the manifest has no versionName");
    }
    let version_name =
        crate::git::truncate_chars(&crate::git::display_safe(name), MAX_VERSION_NAME);

    let mut sdk_lines = text.lines().filter_map(|l| {
        l.strip_prefix("minSdkVersion:'")
            .or_else(|| l.strip_prefix("sdkVersion:'"))
    });
    let (Some(sdk), None) = (sdk_lines.next(), sdk_lines.next()) else {
        bail!(
            "aapt2 shows no or several minSdkVersion lines (the manifest needs <uses-sdk android:minSdkVersion>)"
        );
    };
    let min_sdk = sdk
        .strip_suffix('\'')
        .and_then(decimal_u32)
        .ok_or_else(|| {
            anyhow!(
                "the manifest's minSdkVersion {:?} is not a number (a preview SDK?)",
                crate::git::truncate_chars(&crate::git::display_safe(sdk), 40)
            )
        })?;
    Ok(AppInfo {
        package: package.to_owned(),
        version_code,
        version_name,
        min_sdk,
    })
}

/// What a tool run produced (output capped, see [`run_bounded`]).
struct ToolOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Kills (and reaps) the child unless it has already been waited for.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reads at most `max` bytes, then keeps draining (so the writer never blocks) and sets
/// `overflow`.
fn read_capped(mut pipe: impl Read, max: usize, overflow: &AtomicBool) -> Vec<u8> {
    let mut buf = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let _ = (&mut pipe).take(limit).read_to_end(&mut buf);
    if buf.len() > max {
        buf.truncate(max);
        overflow.store(true, Ordering::SeqCst);
        let _ = std::io::copy(&mut pipe, &mut std::io::sink());
    }
    buf
}

/// A thread reading `pipe` with [`read_capped`].
fn spawn_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    max: usize,
    overflow: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<Vec<u8>>> {
    std::thread::Builder::new()
        .spawn(move || match pipe {
            Some(p) => read_capped(p, max, &overflow),
            None => Vec::new(),
        })
        .context("start a thread")
}

/// Runs `cmd` with stdin from /dev/null, at most `max_stdout` bytes of stdout and
/// [`MAX_TOOL_STDERR`] of stderr, and a deadline; too much output or the deadline kill
/// it and fail.
fn run_bounded(cmd: &mut Command, timeout: Duration, max_stdout: usize) -> Result<ToolOutput> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("timeout out of range"))?;
    let mut child = KillOnDrop(
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let too_much = Arc::new(AtomicBool::new(false));
    let stdout = spawn_reader(child.0.stdout.take(), max_stdout, Arc::clone(&too_much))?;
    let stderr = spawn_reader(
        child.0.stderr.take(),
        MAX_TOOL_STDERR,
        Arc::new(AtomicBool::new(false)),
    )?;
    let poll = Duration::from_millis(5);
    let status = loop {
        if too_much.load(Ordering::SeqCst) {
            bail!("it printed more than {max_stdout} bytes");
        }
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            bail!("it did not finish within {timeout:?}");
        }
        std::thread::sleep(poll);
    };
    // A process it left behind could hold the pipes open: the deadline still applies.
    while !(stdout.is_finished() && stderr.is_finished()) {
        if Instant::now() >= deadline {
            bail!("its output did not end within {timeout:?}");
        }
        std::thread::sleep(poll);
    }
    let stdout = stdout
        .join()
        .map_err(|_| anyhow!("reading its output failed"))?;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow!("reading its output failed"))?;
    if too_much.load(Ordering::SeqCst) {
        bail!("it printed more than {max_stdout} bytes");
    }
    Ok(ToolOutput {
        status,
        stdout,
        stderr,
    })
}

/// A temporary copy (mode 0600, random name, created exclusively) removed on drop.
struct PrivateCopy(PathBuf);

impl PrivateCopy {
    fn write(bytes: &[u8]) -> Result<Self> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).map_err(|e| anyhow!("no system randomness: {e}"))?;
        let name: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("pets-apk-{name}.apk"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        let copy = PrivateCopy(path);
        file.write_all(bytes)
            .with_context(|| format!("write {}", copy.0.display()))?;
        Ok(copy)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `aapt2 dump badging <apk>` with an empty environment; the app's package name,
/// version and minSdkVersion.
fn read_app_info(aapt2: &Path, apk: &Path, timeout: Duration) -> Result<AppInfo> {
    let mut cmd = Command::new(aapt2);
    cmd.env_clear().args(["dump", "badging"]).arg(path_arg(apk));
    let out = run_bounded(&mut cmd, timeout, MAX_TOOL_STDOUT)
        .with_context(|| format!("run {}", aapt2.display()))?;
    if !out.status.success() {
        bail!(
            "aapt2 cannot read the manifest of {} ({}): {}",
            apk.display(),
            out.status,
            crate::git::truncate_chars(
                &crate::git::display_safe(String::from_utf8_lossy(&out.stderr).trim()),
                500
            )
        );
    }
    parse_badging(&String::from_utf8_lossy(&out.stdout))
        .with_context(|| format!("{} (read with aapt2 dump badging)", apk.display()))
}

/// `apksigner` with the JVM option variables removed from its environment.
fn apksigner_command(apksigner: &Path) -> Command {
    let mut cmd = Command::new(apksigner);
    for var in JVM_ENV {
        cmd.env_remove(var);
    }
    cmd
}

/// A path as an apksigner argument: relative paths get a `./` prefix so a name starting
/// with `-` is never read as an option.
fn path_arg(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        Path::new(".").join(path)
    }
}

/// `--subject "CN=…"` or a bare CN → the CN (1-64 printable ASCII characters, a single
/// attribute).
fn parse_subject(subject: &str) -> Result<&str> {
    let cn = subject.strip_prefix("CN=").unwrap_or(subject);
    if cn.contains('=') {
        bail!("--subject must be a single CN (\"CN=<name>\"); other attributes are not supported");
    }
    if cn.is_empty() || cn.len() > MAX_CN_LEN || !cn.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        bail!("--subject CN must be 1-{MAX_CN_LEN} printable ASCII characters");
    }
    Ok(cn)
}

/// An APK signing identity: `gpg://` (the device signs a 32-byte digest as given) with
/// curve nist256p1.
fn check_apk_identity(id: &Slip13Identity) -> Result<()> {
    if id.identity().proto() != Proto::Gpg || id.curve() != Curve::Nist256p1 {
        bail!(
            "identity \"{}\" cannot sign APKs: it needs a gpg:// uri and curve = \"nist256p1\"",
            id.name()
        );
    }
    Ok(())
}

/// The P-256 signature of a verified device answer as DER `ECDSA-Sig-Value`.
fn signature_der(signed: &SignedIdentity) -> Result<Vec<u8>> {
    match signed.signature().parts() {
        SignatureParts::Nist256p1 { r, s } => Ok(ecdsa_der_from_scalars(r, s)?),
        SignatureParts::Ed25519(_) => bail!("the Trezor returned an ed25519 signature"),
    }
}

fn p256_point(key: &PublicKey) -> Result<[u8; 65]> {
    key.p256_uncompressed()
        .ok_or_else(|| anyhow!("the Trezor returned a key that is not nist256p1"))
}

/// Uppercase hex with colons, as the Play Console shows certificate fingerprints.
pub(crate) fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `pets apk init`: the self-signed certificate for the identity's device key.
///
/// Two confirmations: (a) a random 32-byte challenge, to get the public key (verified
/// against the signature and the pin, if any); (b) SHA-256 of the TBSCertificate built
/// for that key. `open` connects to the device only after all local checks passed.
pub(crate) fn init<S: Signer>(
    id: &Slip13Identity,
    subject: &str,
    open: impl FnOnce() -> Result<S>,
) -> Result<Certificate> {
    check_apk_identity(id)?;
    if id.certificate().is_some() {
        bail!(
            "identity \"{}\" already has a certificate; a new one would be a different signer \
             for Android (app updates would fail). Remove it from the config first only if \
             no app was ever signed with it",
            id.name()
        );
    }
    let cn = parse_subject(subject)?;
    let mut signer = open()?;

    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| anyhow!("no system randomness: {e}"))?;
    crate::say(&format!(
        "pets: reading the public key of \"{}\"",
        id.name()
    ));
    let req = SignRequest::for_identity(id, challenge.to_vec(), format!("apk init {}", id.name()));
    let key = signer.sign_identity(&req)?.public_key().clone();
    let tbs = Certificate::build(&p256_point(&key)?, cn)?;

    crate::say(&format!("pets: signing the certificate CN={cn}"));
    let req = SignRequest::for_identity(id, tbs.digest().to_vec(), format!("apk cert {cn}"));
    let signed = signer.sign_identity(&req)?;
    if *signed.public_key() != key {
        bail!("the Trezor returned a different key for the certificate signature");
    }
    // `finish` verifies the signature against the certificate's key (fail closed).
    Ok(tbs.finish(&signature_der(&signed)?)?)
}

/// Prints the result of [`init`]: the config line on stdout, the rest on stderr.
pub(crate) fn print_init(id: &Slip13Identity, cert: &Certificate) -> Result<()> {
    let key = PublicKey::from_p256_uncompressed(cert.public_key())?;
    eprintln!(
        "add to [[identity]] \"{}\" in the config (keep it forever: Android identifies the \
         signer by these exact bytes):",
        id.name()
    );
    println!("certificate = \"{}\"", STANDARD.encode(cert.der()));
    if id.fingerprint().is_none() {
        println!("fingerprint = \"{}\"", key.fingerprint());
    }
    eprintln!("subject: CN={}", cert.subject_cn());
    eprintln!(
        "certificate SHA-256: {}",
        colon_hex(&cert.sha256_fingerprint())
    );
    Ok(())
}

/// Arguments of `pets apk sign`.
#[derive(Debug, Clone)]
pub(crate) struct SignArgs {
    pub input: PathBuf,
    pub output: PathBuf,
    pub replace: bool,
}

/// The tools `pets apk sign` runs (absolute paths, see [`apksigner_path`] and
/// [`aapt2_path`]).
#[derive(Debug, Clone)]
pub(crate) struct Tools {
    pub apksigner: PathBuf,
    pub aapt2: PathBuf,
}

/// What `pets apk sign` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignReport {
    pub certificate_sha256: [u8; 32],
    pub schemes: Vec<SchemeVersion>,
    pub app: AppInfo,
}

/// The temporary output; removed on drop (after [`persist`] it is only a second link).
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn scheme_name(scheme: SchemeVersion) -> &'static str {
    match scheme {
        SchemeVersion::V2 => "v2",
        SchemeVersion::V3 => "v3",
    }
}

/// What the device shows for one scheme's signature:
/// `apk <v2|v3> <package>:<versionName>(<versionCode>) <first 8 hex of content digest>`,
/// at most [`MAX_VISUAL`] characters (a long package name is truncated).
fn visual(app: &AppInfo, content_digest: &[u8; 32], scheme: SchemeVersion) -> String {
    let short = content_digest.get(..4).map(hex).unwrap_or_default();
    let version = format!(
        "{}({})",
        crate::git::truncate_chars(
            &crate::git::display_safe(&app.version_name),
            MAX_VERSION_NAME
        ),
        app.version_code
    );
    // "apk vN " + package + ":" + version + " " + short
    let fixed = version
        .chars()
        .count()
        .saturating_add(short.len())
        .saturating_add(9);
    let package = crate::git::truncate_chars(
        &crate::git::display_safe(&app.package),
        MAX_VISUAL.saturating_sub(fixed),
    );
    format!("apk {} {package}:{version} {short}", scheme_name(scheme))
}

/// `pets apk sign`: parse, read the manifest with `aapt2`, align, sign on the device
/// (two confirmations: v2 and v3), verify with `apksigner`, then move into place without
/// overwriting anything.
pub(crate) fn sign<S: Signer>(
    id: &Slip13Identity,
    args: &SignArgs,
    tools: &Tools,
    open: impl FnOnce() -> Result<S>,
) -> Result<SignReport> {
    sign_with_timeout(id, args, tools, AAPT2_TIMEOUT, open)
}

fn sign_with_timeout<S: Signer>(
    id: &Slip13Identity,
    args: &SignArgs,
    tools: &Tools,
    aapt2_timeout: Duration,
    open: impl FnOnce() -> Result<S>,
) -> Result<SignReport> {
    check_apk_identity(id)?;
    let name = id.name();
    let cert = id.certificate().ok_or_else(|| {
        anyhow!(
            "identity \"{name}\" has no certificate; run `pets apk init {name} --subject \
             \"CN=...\"` and add the printed certificate line to the config"
        )
    })?;
    // The config has checked that the certificate's key is the pinned key.
    if id.fingerprint().is_none() {
        bail!(
            "identity \"{name}\" is not pinned; add the fingerprint printed by `pets apk init` \
             (fingerprint = \"...\") to the config"
        );
    }
    if args.output.symlink_metadata().is_ok() {
        bail!(
            "{} already exists; not overwriting it",
            args.output.display()
        );
    }
    check_apksigner(&tools.apksigner)?;
    check_tool("aapt2", &tools.aapt2)?;

    let bytes = crate::git::read_limited(&args.input, MAX_APK)?;
    // aapt2 reads a private copy of exactly these bytes, so what the device shows and what
    // is signed come from the same input even if the file is replaced meanwhile.
    let copy = PrivateCopy::write(&bytes)?;
    let mut apk = Apk::parse_owned(bytes).with_context(|| format!("{}", args.input.display()))?;
    let v1 = apk.v1_signature_files();
    if !v1.is_empty() {
        bail!(
            "{} contains v1 (JAR) signature files of a previous signer ({}); they would \
             stay next to the new signature. Sign the unsigned build output instead \
             (pets does not remove v1 signatures)",
            args.input.display(),
            crate::git::truncate_chars(&crate::git::display_safe(&v1.join(", ")), 200)
        );
    }
    if apk.has_signing_block() {
        if !args.replace {
            bail!(
                "{} is already signed (APK Signing Block present); pass --replace to remove \
                 the existing signatures",
                args.input.display()
            );
        }
        let _removed = apk.remove_signing_block();
    }
    let app = read_app_info(&tools.aapt2, copy.path(), aapt2_timeout)
        .with_context(|| format!("{}", args.input.display()))?;
    drop(copy);
    // The minSdkVersion is checked once more by apksigner's own manifest parser on the output.
    if app.min_sdk < MIN_SDK {
        bail!(
            "{} ({app}) has minSdkVersion {}; pets signs only apps with minSdkVersion >= \
             {MIN_SDK} (no v1 signatures, which Android < 7.0 needs)",
            args.input.display(),
            app.min_sdk
        );
    }
    apk.align()?;
    let content_digest = apk.content_digest()?;

    let mut signer = open()?;
    let mut schemes = Vec::new();
    let signed_apk = petschaft_apk::sign(&apk, cert, |digest, scheme| {
        schemes.push(scheme);
        let shown = visual(&app, &content_digest, scheme);
        // The same text as on the device, so the user can compare both.
        crate::say(&format!(
            "pets: signing {} with \"{name}\" (confirmation {} of 2); the Trezor shows:\n  {shown}",
            args.input.display(),
            schemes.len(),
        ));
        let device = |e: anyhow::Error| petschaft_apk::Error::Signer(e.into());
        let req = SignRequest::for_identity(id, digest.to_vec(), shown);
        let signed = signer
            .sign_identity(&req)
            .map_err(|e| device(anyhow::Error::new(e)))?;
        // Fail closed: only the certificate's key may sign (the pin already enforces it;
        // `sign` verifies every signature against the certificate as well).
        if p256_point(signed.public_key()).map_err(device)? != *cert.public_key() {
            return Err(device(anyhow!(
                "the Trezor returned a different key than the certificate's"
            )));
        }
        signature_der(&signed).map_err(device)
    })?;
    drop(signer);
    drop(apk);

    let tmp = write_temp(&args.output, &signed_apk)?;
    drop(signed_apk);
    verify_with_apksigner(
        &tools.apksigner,
        &tmp.0,
        cert,
        app.min_sdk,
        APKSIGNER_TIMEOUT,
    )?;
    persist(&tmp, &args.output)?;
    drop(tmp);
    Ok(SignReport {
        certificate_sha256: cert.sha256_fingerprint(),
        schemes,
        app,
    })
}

/// Writes `data` to a new temporary file next to `output`.
fn write_temp(output: &Path, data: &[u8]) -> Result<TempFile> {
    let dir = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = output
        .file_name()
        .ok_or_else(|| anyhow!("-o {} is not a file path", output.display()))?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| anyhow!("no system randomness: {e}"))?;
    let mut tmp_name = OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".pets-{}.tmp", hex(&random)));
    let path = dir.join(tmp_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    let tmp = TempFile(path);
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .context("write the signed APK")?;
    Ok(tmp)
}

/// Moves the verified temporary file to `output`; fails (and leaves `output` alone) if
/// something appeared there in the meantime.
fn persist(tmp: &TempFile, output: &Path) -> Result<()> {
    // A hard link never replaces an existing file (unlike rename); the temporary name
    // is removed when `tmp` is dropped. File systems without hard links (exFAT, some
    // SMB shares) fail here, after the confirmations: nothing is written then.
    std::fs::hard_link(&tmp.0, output).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow!("{} already exists; not overwriting it", output.display())
        } else {
            anyhow!("cannot create {}: {e}", output.display())
        }
    })?;
    Ok(())
}

/// `apksigner verify -v --min-sdk-version <minSdk> --print-certs`; it must succeed,
/// have verified v3 and, for minSdk < 28, v2 (from 28 on Android and apksigner use only
/// v3; `petschaft_apk::sign` has verified the v2 signature itself), and name exactly
/// our certificate. Then a plain
/// `apksigner verify`, where apksigner reads the minSdkVersion from the manifest
/// itself: an independent check of what aapt2 printed (aapt2 does not escape manifest
/// strings, so a crafted versionName could fake its minSdkVersion line).
fn verify_with_apksigner(
    apksigner: &Path,
    apk: &Path,
    cert: &Certificate,
    min_sdk: u32,
    timeout: Duration,
) -> Result<()> {
    let run = |cmd: &mut Command| {
        run_bounded(cmd, timeout, MAX_TOOL_STDOUT)
            .with_context(|| format!("run {}", apksigner.display()))
    };
    let out = run(apksigner_command(apksigner)
        .args(["verify", "-v", "--min-sdk-version"])
        .arg(min_sdk.to_string())
        .arg("--print-certs")
        .arg(path_arg(apk)))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        bail!("apksigner rejected the signed APK (nothing was written):\n{text}");
    }
    let expected = format!(
        "Signer #1 certificate SHA-256 digest: {}",
        hex(&cert.sha256_fingerprint())
    );
    if !text.lines().any(|l| l.trim() == expected) || text.contains("Signer #2") {
        bail!("apksigner shows another signer than the certificate (nothing was written):\n{text}");
    }
    let schemes: &[u32] = if min_sdk < V3_MIN_SDK { &[2, 3] } else { &[3] };
    for scheme in schemes {
        let line =
            format!("Verified using v{scheme} scheme (APK Signature Scheme v{scheme}): true");
        if !text.lines().any(|l| l.trim() == line) {
            bail!(
                "apksigner did not verify the v{scheme} signature (nothing was written):\n{text}"
            );
        }
    }
    let out = run(apksigner_command(apksigner)
        .arg("verify")
        .arg(path_arg(apk)))?;
    if !out.status.success() {
        bail!(
            "apksigner rejected the signed APK for the minSdkVersion in its manifest (nothing \
             was written):\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Prints the result of [`sign`].
pub(crate) fn print_sign(args: &SignArgs, report: &SignReport) {
    let schemes: Vec<&str> = report.schemes.iter().map(|s| scheme_name(*s)).collect();
    eprintln!(
        "signed {} ({}, APK Signature Scheme {}, minSdkVersion {}), verified by apksigner",
        args.output.display(),
        report.app,
        schemes.join(" + "),
        report.app.min_sdk,
    );
    eprintln!(
        "certificate SHA-256: {}",
        colon_hex(&report.certificate_sha256)
    );
}

/// `pets apk verify`: `apksigner verify -v --print-certs [--min-sdk-version N]`, output
/// passed through.
pub(crate) fn verify(apksigner: &Path, apk: &Path, min_sdk: Option<u32>) -> Result<()> {
    check_apksigner(apksigner)?;
    let mut cmd = apksigner_command(apksigner);
    cmd.args(["verify", "-v", "--print-certs"]);
    if let Some(n) = min_sdk {
        cmd.arg("--min-sdk-version").arg(n.to_string());
    }
    let status = cmd
        .arg(path_arg(apk))
        .status()
        .with_context(|| format!("run {}", apksigner.display()))?;
    if !status.success() {
        bail!("apksigner: {} does not verify", apk.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
