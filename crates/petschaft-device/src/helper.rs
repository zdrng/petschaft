//! [`HelperSigner`]: spawns the Python helper and drives `docs/helper-protocol.md`.
//!
//! The protocol state machine only sees a byte reader, a byte writer and a
//! [`HelperProcess`] handle, so tests drive it through in-memory pipes and a fake
//! helper thread; [`HelperSigner::spawn`] plugs in the real child process.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use petschaft_core::{Curve, PassphrasePolicy, Proto, Transport};
use petschaft_helper_proto::{
    self as proto, Credential, DeviceInfo, EventKind, HelperMessage, HostMessage, Validate as _,
};

use crate::error::Error;
use crate::signer::{SignRequest, SignedIdentity, Signer, Ui};
use crate::store::{CredentialStore, StoreError};

/// Environment variables passed through to the helper; everything else is cleared.
///
/// - `HOME`, `TMPDIR`: harmless process basics some libraries consult.
/// - `LANG`, `LC_ALL`, `LC_CTYPE`: text encoding of diagnostics on stderr.
/// - `DBUS_SYSTEM_BUS_ADDRESS`: Bluetooth on Linux (BlueZ on the system bus) when the
///   bus lives at a non-default address.
///
/// Deliberately not passed: `PYTHON*` (also ignored by `-I`), `TREZOR_PATH` (transport
/// is chosen by `hello.transport` only), `PATH` (the interpreter is an absolute path),
/// `LD_*`/`DYLD_*` and anything else.
pub const PASSED_ENV: &[&str] = &[
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "DBUS_SYSTEM_BUS_ADDRESS",
];

/// `hello.app_name` used by petschaft.
pub const APP_NAME: &str = "petschaft";

/// At most this many `event` messages per request; more is treated as a protocol
/// violation (a flood would otherwise spin the UI until the deadline).
const MAX_EVENTS_PER_REQUEST: usize = 64;

/// Overall deadline of every helper request (`hello` and each signature).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Deadlines of the spec, injectable for tests.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timeouts {
    /// `hello` until the first event or `ready`.
    pub hello_first: Duration,
    /// Every request overall (including `hello`).
    pub request: Duration,
    /// After closing stdin on drop: how long to wait for an orderly exit before killing.
    pub shutdown_grace: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            // Covers device discovery (BLE scan up to 15 s), PIN entry and the OS Bluetooth
            // pairing dialog, none of which produce an event.
            hello_first: Duration::from_secs(120),
            request: REQUEST_TIMEOUT,
            shutdown_grace: Duration::from_secs(2),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------

/// Interpreter and script of the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPaths {
    pub python: PathBuf,
    pub script: PathBuf,
}

impl HelperPaths {
    /// Compile-time `PETSCHAFT_HELPER_PYTHON` / `PETSCHAFT_HELPER_SCRIPT` (fixed Nix store paths
    /// of release builds) take precedence; otherwise the runtime environment variables
    /// of the same names; otherwise [`Error::HelperNotConfigured`]. Both must be
    /// absolute paths (no `PATH` lookup). An empty value counts as unset.
    pub fn resolve() -> Result<Self, Error> {
        Ok(HelperPaths {
            python: resolve_path(
                "PETSCHAFT_HELPER_PYTHON",
                option_env!("PETSCHAFT_HELPER_PYTHON"),
                std::env::var_os("PETSCHAFT_HELPER_PYTHON"),
            )?,
            script: resolve_path(
                "PETSCHAFT_HELPER_SCRIPT",
                option_env!("PETSCHAFT_HELPER_SCRIPT"),
                std::env::var_os("PETSCHAFT_HELPER_SCRIPT"),
            )?,
        })
    }
}

pub(crate) fn resolve_path(
    name: &str,
    compile_time: Option<&str>,
    runtime: Option<OsString>,
) -> Result<PathBuf, Error> {
    let chosen = match compile_time.filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => match runtime.filter(|s| !s.is_empty()) {
            Some(s) => PathBuf::from(s),
            None => {
                return Err(Error::HelperNotConfigured(format!(
                    "{name} is not set (neither at build time nor in the environment)"
                )));
            }
        },
    };
    if !chosen.is_absolute() {
        return Err(Error::HelperNotConfigured(format!(
            "{name} must be an absolute path"
        )));
    }
    Ok(chosen)
}

/// Parameters of `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOptions {
    /// Shown on the Trezor during pairing; default [`APP_NAME`].
    pub app_name: String,
    /// Shown on the Trezor during pairing (1-64 printable ASCII characters).
    pub host_name: String,
    pub transport: Transport,
}

impl ConnectOptions {
    pub fn new(host_name: impl Into<String>, transport: Transport) -> Self {
        ConnectOptions {
            app_name: APP_NAME.to_owned(),
            host_name: host_name.into(),
            transport,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Process handle
// ---------------------------------------------------------------------------------------

/// What the state machine needs from the helper process.
pub(crate) trait HelperProcess: Send {
    /// Kill immediately and reap.
    fn kill(&mut self);
    /// stdin has been closed: wait up to `grace` for the process to exit, then kill
    /// and reap.
    fn shutdown(&mut self, grace: Duration);
}

struct ChildProcess(Child);

impl HelperProcess for ChildProcess {
    fn kill(&mut self) {
        // Errors mean it has already exited; `wait` reaps it either way.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }

    fn shutdown(&mut self, grace: Duration) {
        if let Some(end) = Instant::now().checked_add(grace) {
            loop {
                match self.0.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(10)),
                    _ => break,
                }
            }
        }
        self.kill();
    }
}

// ---------------------------------------------------------------------------------------
// Link: transport + process lifecycle
// ---------------------------------------------------------------------------------------

/// What the reader thread delivers.
enum Incoming {
    Message(HelperMessage),
    /// Clean EOF between frames.
    Eof,
    /// Framing/decoding/validation error (text contains no peer data).
    Invalid(String),
}

/// Owns the helper's stdin, the channel from the reader thread and the process.
/// Dropping it shuts the helper down.
struct Link {
    writer: Option<Box<dyn Write + Send>>,
    rx: Receiver<Incoming>,
    process: Option<Box<dyn HelperProcess>>,
    timeouts: Timeouts,
}

fn reader_loop<R: Read>(mut reader: R, tx: SyncSender<Incoming>) {
    loop {
        let item = match proto::read_helper_message(&mut reader) {
            Ok(Some(m)) => Incoming::Message(m),
            Ok(None) => Incoming::Eof,
            Err(e) => Incoming::Invalid(e.to_string()),
        };
        let last = !matches!(item, Incoming::Message(_));
        // A send error means the receiver is gone: stop reading.
        if tx.send(item).is_err() || last {
            return;
        }
    }
}

impl Link {
    fn new<R>(
        reader: R,
        writer: Box<dyn Write + Send>,
        process: Box<dyn HelperProcess>,
        timeouts: Timeouts,
    ) -> Result<Self, Error>
    where
        R: Read + Send + 'static,
    {
        // Capacity 1: the reader blocks (backpressure) instead of buffering a flood.
        let (tx, rx) = mpsc::sync_channel(1);
        let mut link = Link {
            writer: Some(writer),
            rx,
            process: Some(process),
            timeouts,
        };
        // The thread is detached: it ends when the helper's stdout closes (the process
        // exited or was killed) or when the receiver is dropped.
        if let Err(e) = thread::Builder::new()
            .name("petschaft-helper-reader".into())
            .spawn(move || reader_loop(reader, tx))
        {
            link.kill();
            return Err(Error::Spawn(format!("reader thread: {e}")));
        }
        Ok(link)
    }

    fn is_closed(&self) -> bool {
        self.writer.is_none()
    }

    /// Kill the helper now and close the link.
    fn kill(&mut self) {
        self.writer = None;
        if let Some(mut p) = self.process.take() {
            p.kill();
        }
    }

    /// Close stdin and let the helper exit on its own (it does after EOF or a fatal
    /// error), killing it after the grace period.
    fn shutdown(&mut self) {
        self.writer = None;
        if let Some(mut p) = self.process.take() {
            p.shutdown(self.timeouts.shutdown_grace);
        }
    }

    /// Kill the helper and produce a protocol error.
    fn violation(&mut self, reason: impl Into<String>) -> Error {
        self.kill();
        Error::Protocol(reason.into())
    }

    fn send(&mut self, msg: &HostMessage) -> Result<(), Error> {
        let Some(w) = self.writer.as_mut() else {
            return Err(Error::Closed);
        };
        match proto::write_host_message(w, msg) {
            Ok(()) => Ok(()),
            Err(proto::Error::Io(e)) => {
                self.kill();
                Err(Error::Io(e.to_string()))
            }
            // Messages are validated before they reach here; still never send garbage.
            Err(e) => Err(Error::InvalidRequest(e.to_string())),
        }
    }

    /// Fail if the helper sent something while no request was outstanding.
    fn check_idle(&mut self) -> Result<(), Error> {
        match self.rx.try_recv() {
            Err(TryRecvError::Empty) => Ok(()),
            Ok(Incoming::Message(_)) => Err(self.violation("unsolicited message")),
            Ok(Incoming::Invalid(reason)) => Err(self.violation(reason)),
            Ok(Incoming::Eof) | Err(TryRecvError::Disconnected) => {
                self.kill();
                Err(Error::HelperExited)
            }
        }
    }

    fn recv(&mut self, deadline: Instant, stage: &'static str) -> Result<HelperMessage, Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.rx.recv_timeout(remaining) {
            Ok(Incoming::Message(m)) => Ok(m),
            Ok(Incoming::Invalid(reason)) => Err(self.violation(reason)),
            Ok(Incoming::Eof) | Err(RecvTimeoutError::Disconnected) => {
                self.kill();
                Err(Error::HelperExited)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.kill();
                Err(Error::Timeout(stage))
            }
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn deadline_after(d: Duration) -> Instant {
    let now = Instant::now();
    // Overflow is impossible for the spec's durations; fall back to "now" (expire
    // immediately) rather than to "never".
    now.checked_add(d).unwrap_or(now)
}

// ---------------------------------------------------------------------------------------
// HelperSigner
// ---------------------------------------------------------------------------------------

/// [`Signer`] backed by the Python helper (one helper process per instance).
pub struct HelperSigner<U: Ui> {
    link: Link,
    ui: U,
    device: DeviceInfo,
    next_id: u32,
    store_warning: Option<StoreError>,
}

impl<U: Ui> std::fmt::Debug for HelperSigner<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperSigner")
            .field("device", &self.device)
            .field("closed", &self.link.is_closed())
            .finish_non_exhaustive()
    }
}

/// Build the helper command line and environment (see [`PASSED_ENV`]).
pub(crate) fn helper_command(paths: &HelperPaths) -> Command {
    let mut cmd = Command::new(&paths.python);
    // -I: isolated mode (no PYTHON* env, no user site, no cwd on sys.path);
    // -B: never write bytecode caches, so the helper writes nothing to disk.
    cmd.arg("-I")
        .arg("-B")
        .arg(&paths.script)
        .env_clear()
        .current_dir(Path::new("/"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for key in PASSED_ENV {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd
}

impl<U: Ui> HelperSigner<U> {
    /// Start the helper and complete `hello` (including pairing if the device asks
    /// for it). The credential is loaded from `store` before and stored after.
    pub fn spawn(
        paths: &HelperPaths,
        options: &ConnectOptions,
        ui: U,
        store: &dyn CredentialStore,
    ) -> Result<Self, Error> {
        Self::spawn_with(paths, options, ui, store, Timeouts::default())
    }

    pub(crate) fn spawn_with(
        paths: &HelperPaths,
        options: &ConnectOptions,
        ui: U,
        store: &dyn CredentialStore,
        timeouts: Timeouts,
    ) -> Result<Self, Error> {
        // Validate before starting a process.
        hello_message(options, None)?;
        let mut child = helper_command(paths)
            .spawn()
            .map_err(|e| Error::Spawn(format!("{}: {e}", paths.python.display())))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Spawn("helper pipes unavailable".into()));
        };
        Self::connect(
            stdout,
            Box::new(stdin),
            Box::new(ChildProcess(child)),
            options,
            ui,
            store,
            timeouts,
        )
    }

    /// Run the handshake over arbitrary streams. On error the link is dropped, which
    /// shuts the helper down (it has already been killed for timeouts/violations).
    pub(crate) fn connect<R>(
        reader: R,
        writer: Box<dyn Write + Send>,
        process: Box<dyn HelperProcess>,
        options: &ConnectOptions,
        ui: U,
        store: &dyn CredentialStore,
        timeouts: Timeouts,
    ) -> Result<Self, Error>
    where
        R: Read + Send + 'static,
    {
        let mut link = Link::new(reader, writer, process, timeouts)?;

        let mut store_warning = None;
        let stored = match store.load() {
            // A stored credential that is not valid on the wire is ignored (pair again).
            Ok(Some(c)) if c.validate().is_err() => {
                store_warning = Some(StoreError::Corrupt);
                None
            }
            Ok(c) => c,
            Err(e) => {
                store_warning = Some(e);
                None
            }
        };
        let hello = hello_message(options, stored)?;

        let ready = handshake(&mut link, &ui, &hello)?;

        if let Some(new) = &ready.credential
            && let Err(e) = store.store(new)
        {
            store_warning = Some(e);
        }
        Ok(HelperSigner {
            link,
            ui,
            device: ready.device,
            next_id: 1,
            store_warning,
        })
    }

    /// Device information from `ready.device`.
    pub fn device(&self) -> &DeviceInfo {
        &self.device
    }

    /// Set if the credential could not be loaded or a new one could not be stored
    /// (the connection itself works; the next run will have to pair again).
    pub fn store_warning(&self) -> Option<&StoreError> {
        self.store_warning.as_ref()
    }

    /// `false` after a fatal error, timeout or protocol violation.
    pub fn is_open(&self) -> bool {
        !self.link.is_closed()
    }

    fn sign_inner(&mut self, req: &SignRequest) -> Result<SignedIdentity, Error> {
        if self.link.is_closed() {
            return Err(Error::Closed);
        }
        let id = self.next_id;
        if id == 0 {
            // Ids are never reused; 2^32-1 requests exhaust them.
            self.link.shutdown();
            return Err(Error::Closed);
        }
        let msg = sign_message(id, req)?;
        self.next_id = id.checked_add(1).unwrap_or(0);
        self.link.check_idle()?;
        let deadline = deadline_after(self.link.timeouts.request);
        self.link.send(&HostMessage::SignIdentity(msg))?;

        let mut events = 0usize;
        loop {
            match self.link.recv(deadline, "sign_identity")? {
                HelperMessage::Event(ev) => {
                    events = events.saturating_add(1);
                    if events > MAX_EVENTS_PER_REQUEST {
                        return Err(self.link.violation("too many events"));
                    }
                    match ev.event {
                        EventKind::Button => self.ui.confirm_on_device(),
                        EventKind::PairingCodeRequired => {
                            return Err(self
                                .link
                                .violation("pairing_code_required outside of hello"));
                        }
                    }
                }
                HelperMessage::Signed(s) => {
                    if s.id != id {
                        return Err(self.link.violation("signed: id does not match the request"));
                    }
                    // Verification failures are errors, but not protocol violations:
                    // the connection stays usable (e.g. retry with the right passphrase).
                    return SignedIdentity::from_device(req, &s.public_key, &s.signature);
                }
                HelperMessage::Error(e) => {
                    let id_ok = match e.id {
                        Some(got) => got == id,
                        // `null` is only for protocol errors, which are fatal.
                        None => e.fatal,
                    };
                    if !id_ok {
                        return Err(self.link.violation("error: id does not match the request"));
                    }
                    if e.fatal {
                        self.link.shutdown();
                    }
                    return Err(Error::from(&e));
                }
                HelperMessage::Ready(_) => {
                    return Err(self.link.violation("unexpected ready"));
                }
            }
        }
    }
}

impl<U: Ui> Signer for HelperSigner<U> {
    fn sign_identity(&mut self, req: &SignRequest) -> Result<SignedIdentity, Error> {
        self.sign_inner(req)
    }
}

fn hello_message(
    options: &ConnectOptions,
    credential: Option<Credential>,
) -> Result<HostMessage, Error> {
    let transport = match options.transport {
        Transport::Auto => proto::Transport::Auto,
        Transport::Usb => proto::Transport::Usb,
        Transport::Ble => proto::Transport::Ble,
    };
    let mut hello = proto::Hello {
        version: proto::PROTOCOL_VERSION,
        app_name: options.app_name.clone(),
        host_name: options.host_name.clone(),
        transport,
        credential,
    };
    // A stored credential that is not valid on the wire is ignored (pair again).
    if hello
        .credential
        .as_ref()
        .is_some_and(|c| c.validate().is_err())
    {
        hello.credential = None;
    }
    let msg = HostMessage::Hello(hello);
    msg.validate()
        .map_err(|e| Error::InvalidRequest(e.to_string()))?;
    Ok(msg)
}

fn sign_message(id: u32, req: &SignRequest) -> Result<proto::SignIdentity, Error> {
    let identity = req.identity().identity();
    let msg = proto::SignIdentity {
        id,
        identity: proto::Identity {
            proto: match identity.proto() {
                Proto::Ssh => proto::Proto::Ssh,
                Proto::Gpg => proto::Proto::Gpg,
            },
            user: identity.user().map(str::to_owned),
            host: identity.host().to_owned(),
            port: identity.port().map(str::to_owned),
            path: identity.path().map(str::to_owned),
            index: identity.index(),
        },
        curve: match req.identity().curve() {
            Curve::Ed25519 => proto::Curve::Ed25519,
            Curve::Nist256p1 => proto::Curve::Nist256p1,
        },
        challenge_hidden: req.challenge_hidden().to_vec(),
        challenge_visual: req.challenge_visual().to_owned(),
        passphrase: match req.identity().passphrase() {
            PassphrasePolicy::Ask => proto::Passphrase::Ask,
            PassphrasePolicy::Standard => proto::Passphrase::Standard,
        },
    };
    msg.validate()
        .map_err(|e| Error::InvalidRequest(e.to_string()))?;
    Ok(msg)
}

/// `hello` → events → `ready`. Every failure path leaves the link closed.
fn handshake<U: Ui>(link: &mut Link, ui: &U, hello: &HostMessage) -> Result<proto::Ready, Error> {
    let overall = deadline_after(link.timeouts.request);
    let first = deadline_after(link.timeouts.hello_first).min(overall);
    link.check_idle()?;
    link.send(hello)?;

    let mut got_first = false;
    let mut pairing_done = false;
    let mut events = 0usize;
    loop {
        let msg = if got_first {
            link.recv(overall, "hello")?
        } else {
            link.recv(first, "hello: first response")?
        };
        got_first = true;
        match msg {
            HelperMessage::Event(ev) => {
                events = events.saturating_add(1);
                if events > MAX_EVENTS_PER_REQUEST {
                    return Err(link.violation("too many events"));
                }
                match ev.event {
                    EventKind::Button => ui.confirm_on_device(),
                    EventKind::PairingCodeRequired => {
                        if pairing_done {
                            return Err(link.violation("pairing code requested twice"));
                        }
                        pairing_done = true;
                        let code = match ui.pairing_code() {
                            Ok(code) => code.trim().to_owned(),
                            Err(e) => {
                                link.kill();
                                return Err(e);
                            }
                        };
                        let reply = HostMessage::PairingCode(proto::PairingCode { code });
                        if reply.validate().is_err() {
                            link.kill();
                            return Err(Error::InvalidPairingCode);
                        }
                        if Instant::now() >= overall {
                            link.kill();
                            return Err(Error::Timeout("hello"));
                        }
                        link.send(&reply)?;
                    }
                }
            }
            HelperMessage::Ready(ready) => {
                if ready.credential.is_some() && !pairing_done {
                    // Spec: a credential is only issued after code-entry pairing.
                    return Err(link.violation("credential issued without pairing"));
                }
                return Ok(ready);
            }
            HelperMessage::Error(e) => {
                if e.id.is_some() {
                    return Err(link.violation("error: id must be null for hello"));
                }
                // `hello` is sent exactly once, so any error ends this helper.
                link.shutdown();
                return Err(Error::from(&e));
            }
            HelperMessage::Signed(_) => {
                return Err(link.violation("unexpected signed during hello"));
            }
        }
    }
}
