//! `pets agent`: an SSH agent for slip13 identities (design: `docs/agent.md`).
//!
//! Threads (std only):
//!
//! - the accept loop ([`serve`]), which starts one thread per client and refuses
//!   clients beyond [`MAX_CLIENTS`];
//! - one thread per client ([`serve_client`]): reads messages, keeps the verified
//!   session bindings of its connection and applies the signing policy of
//!   `petschaft_agent::authorize`;
//! - one device worker ([`Agent::new`]), the only owner of the device connection: sign
//!   requests of all clients are serialized through a bounded channel. The connection
//!   is opened lazily on the first request and dropped after any error, so the next
//!   request opens a fresh one. A job that waited too long in the queue is dropped
//!   instead of being shown on the device late; if the worker is gone, the process
//!   exits so the service manager restarts it.
//!
//! The protocol parsing and the policy live in `petschaft-agent`; signatures are
//! verified (and checked against the pin derived from `public_key`) inside
//! `petschaft-device`, as for every other signature.

mod socket;
#[cfg(test)]
mod tests;

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, TrySendError};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use petschaft_agent::{Request, SessionBind, authorize, parse_request, parse_userauth};
use petschaft_core::{Config, Fingerprint, IdentityConfig, Slip13Identity};
use petschaft_device::{
    Credential, CredentialStore, REQUEST_TIMEOUT, SignRequest, SignedIdentity, Signer, StoreError,
    Ui,
};

pub(crate) use socket::{bind, default_socket_path};

/// Most concurrently served clients; further connections are closed at once.
pub(crate) const MAX_CLIENTS: usize = 16;
/// A client that sends nothing for this long is disconnected (ssh talks to the agent
/// only during authentication).
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Bound for writing one reply to a client that does not read.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Most session bindings per connection (OpenSSH's agent uses the same limit). One
/// more is a protocol error: the connection is closed.
const MAX_BINDINGS: usize = 16;
/// Longest user name (after escaping) shown on the device and in the log.
const MAX_USER_CHARS: usize = 32;
/// Characters of the bound host key's fingerprint shown on the device.
const HOST_TAG_CHARS: usize = 8;
/// Log lines a client can cause without the device (denials, invalid bindings,
/// protocol errors, refused connections): at most this many per [`NOISY_WINDOW`].
const NOISY_PER_WINDOW: u32 = 10;
const NOISY_WINDOW: Duration = Duration::from_secs(60);
/// Bound for one call of the OS secret store from the device worker ([`TimedStore`]).
pub(crate) const KEYRING_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_QUEUE_WAIT: Duration = Duration::from_secs(30);

/// Time limits of the daemon ([`Limits::DEFAULT`]; tests use shorter ones).
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    /// A sign job that waited longer than this in the device queue (behind another
    /// confirmation) is dropped: the user is no longer waiting for it.
    pub(crate) max_queue_wait: Duration,
    /// How long a client waits for the device worker's answer; then it gets
    /// `SSH_AGENT_FAILURE`, so a hung worker cannot hold its connection forever.
    pub(crate) max_reply_wait: Duration,
    /// A connection is closed after this long, whatever it sends (ssh uses one
    /// connection per authentication), so no client holds a slot forever.
    pub(crate) max_connection_time: Duration,
    /// Called when the device worker is gone (only after a panic; release builds
    /// abort on panic anyway).
    pub(crate) on_worker_death: fn(),
}

impl Limits {
    pub(crate) const DEFAULT: Limits = Limits {
        max_queue_wait: MAX_QUEUE_WAIT,
        // Queue, then opening the connection (`hello`) and signing, each with the
        // helper's deadline and a credential store call, plus a margin.
        max_reply_wait: MAX_QUEUE_WAIT
            .saturating_add(REQUEST_TIMEOUT.saturating_mul(2))
            .saturating_add(KEYRING_TIMEOUT.saturating_mul(2))
            .saturating_add(Duration::from_secs(10)),
        max_connection_time: Duration::from_secs(600),
        on_worker_death: exit_on_worker_death,
    };
}

/// Without the device worker no request can be served: exit non-zero so systemd /
/// launchd restart the agent.
fn exit_on_worker_death() {
    log("the device worker stopped; exiting (the service manager restarts the agent)");
    std::process::exit(1);
}

/// Log one line to stderr (the journal / launchd log). Callers pass only sanitized or
/// fixed text, never secrets.
pub(crate) fn log(msg: &str) {
    eprintln!("pets agent: {msg}");
}

/// User-controlled text made safe for the device display and the log: ASCII graphic
/// characters are kept, everything else (spaces, controls, non-ASCII) is escaped
/// (`\u{..}`), and the result is cut to [`MAX_USER_CHARS`] characters plus `...`.
/// The output is always printable ASCII, at most `MAX_USER_CHARS + 3` characters.
pub(crate) fn display_safe(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let piece: String = if c.is_ascii_graphic() {
            c.to_string()
        } else {
            c.escape_unicode().collect()
        };
        if out.len().saturating_add(piece.len()) > MAX_USER_CHARS {
            out.push_str("...");
            break;
        }
        out.push_str(&piece);
    }
    out
}

/// `challenge_visual` of a login: `ssh login <user> (<identity>) <tag>`, where the tag
/// is the first [`HOST_TAG_CHARS`] base64 characters of the bound host key's
/// fingerprint (tells concurrent logins apart). At most 89 printable ASCII characters
/// (protocol limit 128): `user` is escaped by [`display_safe`], names are at most 32
/// characters of `[a-z0-9-]`, fingerprints are base64.
fn challenge_visual(user: &str, name: &str, host: &Fingerprint) -> String {
    let fp = host.as_str();
    let tag: String = fp
        .strip_prefix("SHA256:")
        .unwrap_or(fp)
        .chars()
        .take(HOST_TAG_CHARS)
        .collect();
    format!("ssh login {} ({name}) {tag}", display_safe(user))
}

/// Rate limit for [`Agent::log_noisy`]: a fixed window of [`NOISY_WINDOW`].
struct LogLimiter {
    window_start: Instant,
    logged: u32,
    suppressed: u64,
}

impl LogLimiter {
    fn new(now: Instant) -> Self {
        LogLimiter {
            window_start: now,
            logged: 0,
            suppressed: 0,
        }
    }

    /// Whether one more line may be logged at `now`, and the number of lines
    /// suppressed in the window that just ended (to be reported first).
    fn admit(&mut self, now: Instant) -> (Option<u64>, bool) {
        let mut report = None;
        if now.saturating_duration_since(self.window_start) >= NOISY_WINDOW {
            report = (self.suppressed > 0).then_some(self.suppressed);
            *self = LogLimiter::new(now);
        }
        if self.logged < NOISY_PER_WINDOW {
            self.logged = self.logged.saturating_add(1);
            (report, true)
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            (report, false)
        }
    }
}

/// An identity the agent offers: a slip13 identity with `public_key` and `host_keys`.
#[derive(Debug, Clone)]
pub(crate) struct AgentKey {
    identity: Slip13Identity,
    key_blob: Vec<u8>,
    algorithm: &'static str,
    comment: String,
}

impl AgentKey {
    fn from_identity(id: &Slip13Identity) -> Option<Self> {
        let key = id.public_key()?;
        if id.host_keys().is_empty() {
            return None;
        }
        Some(AgentKey {
            identity: id.clone(),
            key_blob: key.openssh_blob(),
            algorithm: key.openssh_algorithm(),
            comment: id.comment().as_str().to_owned(),
        })
    }

    fn name(&self) -> &str {
        self.identity.name().as_str()
    }

    fn host_keys(&self) -> &[Fingerprint] {
        self.identity.host_keys()
    }
}

/// The identities of `config` that the agent offers (file order), and a note for each
/// slip13 identity that is left out.
pub(crate) fn agent_keys(config: &Config) -> (Vec<AgentKey>, Vec<String>) {
    let mut keys = Vec::new();
    let mut notes = Vec::new();
    for id in config.identities() {
        let IdentityConfig::Slip13(id) = id else {
            continue;
        };
        match AgentKey::from_identity(id) {
            Some(k) => keys.push(k),
            None => notes.push(format!(
                "identity \"{}\" is not offered: it needs public_key and host_keys",
                id.name()
            )),
        }
    }
    (keys, notes)
}

/// The start-up log line: which config was loaded and which identities are offered.
pub(crate) fn startup_summary(config_path: &Path, keys: &[AgentKey]) -> String {
    let names: Vec<&str> = keys.iter().map(AgentKey::name).collect();
    format!(
        "config {}: {} identit{} offered ({})",
        config_path.display(),
        keys.len(),
        if keys.len() == 1 { "y" } else { "ies" },
        names.join(", ")
    )
}

/// Opens a device connection for the worker. Called on the worker thread, so the
/// signer itself need not be `Send`.
pub(crate) type SignerFactory =
    Box<dyn FnMut() -> Result<Box<dyn Signer>, petschaft_device::Error> + Send>;

enum JobError {
    /// Waited longer than this many seconds in the queue.
    Stale(u64),
    Device(petschaft_device::Error),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobError::Stale(s) => write!(
                f,
                "waited more than {s} s for the device (behind another confirmation); dropped"
            ),
            JobError::Device(e) => e.fmt(f),
        }
    }
}

type JobResult = Result<SignedIdentity, JobError>;

struct Job {
    request: SignRequest,
    queued: Instant,
    reply: mpsc::Sender<JobResult>,
}

/// Shared state of the daemon (the config is read once, at start).
pub(crate) struct Agent {
    keys: Vec<AgentKey>,
    jobs: mpsc::SyncSender<Job>,
    limits: Limits,
    noisy: Mutex<LogLimiter>,
}

impl Agent {
    /// Start the device worker thread; `open` is called lazily on it.
    pub(crate) fn new(keys: Vec<AgentKey>, open: SignerFactory) -> std::io::Result<Self> {
        Self::with_limits(keys, open, Limits::DEFAULT)
    }

    pub(crate) fn with_limits(
        keys: Vec<AgentKey>,
        open: SignerFactory,
        limits: Limits,
    ) -> std::io::Result<Self> {
        let (jobs, rx) = mpsc::sync_channel::<Job>(MAX_CLIENTS);
        let max_wait = limits.max_queue_wait;
        std::thread::Builder::new()
            .name("pets-agent-device".into())
            .spawn(move || device_worker(open, &rx, max_wait))?;
        Ok(Agent {
            keys,
            jobs,
            limits,
            noisy: Mutex::new(LogLimiter::new(Instant::now())),
        })
    }

    /// Log a line a client can cause without the device, rate limited (at most
    /// [`NOISY_PER_WINDOW`] per minute; the number suppressed is logged with the next
    /// line after the minute).
    fn log_noisy(&self, msg: &str) {
        let (report, admit) = self
            .noisy
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admit(Instant::now());
        if let Some(n) = report {
            log(&format!(
                "{n} similar log lines suppressed in the last minute"
            ));
        }
        if admit {
            log(msg);
        }
    }

    /// The `(key blob, comment)` pairs of `SSH_AGENT_IDENTITIES_ANSWER`.
    fn identities(&self) -> Vec<(Vec<u8>, String)> {
        self.keys
            .iter()
            .map(|k| (k.key_blob.clone(), k.comment.clone()))
            .collect()
    }

    /// Reply body for one request (`None`: close the connection); updates the
    /// connection state.
    fn handle(&self, conn: &mut Connection, request: Request) -> Option<Vec<u8>> {
        Some(match request {
            Request::RequestIdentities => petschaft_agent::identities_answer(&self.identities()),
            Request::SessionBind(bind) => {
                if conn.bindings.len() >= MAX_BINDINGS {
                    self.log_noisy(&format!(
                        "closing connection: more than {MAX_BINDINGS} session bindings"
                    ));
                    return None;
                }
                conn.bindings.push(bind);
                petschaft_agent::success()
            }
            Request::InvalidSessionBind(reason) => {
                self.log_noisy(&format!(
                    "invalid session-bind ({reason}); refusing all signatures on this connection"
                ));
                conn.tainted = true;
                petschaft_agent::failure()
            }
            Request::Sign { key_blob, data, .. } => match self.sign(conn, &key_blob, &data) {
                Ok(body) => body,
                Err(reason) => {
                    self.log_noisy(&format!("denied: {reason}"));
                    petschaft_agent::failure()
                }
            },
            // add/remove/lock/other extensions: never supported.
            Request::Unsupported(_) => petschaft_agent::failure(),
        })
    }

    /// The signing rules of `docs/agent.md`; `Err` is the (log-safe) denial reason.
    fn sign(&self, conn: &Connection, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let Some(key) = self.keys.iter().find(|k| k.key_blob == key_blob) else {
            return Err(format!(
                "key {} is not offered by this agent",
                Fingerprint::of_openssh_blob(key_blob)
            ));
        };
        let name = key.name();
        if conn.tainted {
            return Err(format!(
                "\"{name}\": this connection sent an invalid session-bind"
            ));
        }
        let auth = parse_userauth(data).map_err(|d| format!("\"{name}\": {d}"))?;
        authorize(&conn.bindings, &auth, &key.key_blob, key.host_keys())
            .map_err(|d| format!("\"{name}\": {d}"))?;
        if auth.algorithm != key.algorithm {
            return Err(format!(
                "\"{name}\": {}",
                petschaft_agent::Denied::KeyMismatch
            ));
        }
        let user = display_safe(&auth.user);
        // `authorize` has checked that there is a binding.
        let Some(host) = conn.bindings.last().map(SessionBind::host_key_fingerprint) else {
            return Err(format!("\"{name}\": {}", petschaft_agent::Denied::NotBound));
        };
        let visual = challenge_visual(&auth.user, name, &host);
        let request = SignRequest::for_identity(&key.identity, data.to_vec(), visual.clone());
        log(&format!("sign request: {visual}, host key {host}"));
        let signed = self
            .device_sign(request)
            .map_err(|e| format!("\"{name}\": device: {e}"))?;
        // Defense in depth: the pin derived from public_key was already checked inside
        // petschaft-device.
        if signed.public_key().openssh_blob() != key.key_blob {
            return Err(format!(
                "\"{name}\": the Trezor signed with a different key"
            ));
        }
        log(&format!("signed: ssh login {user} ({name})"));
        Ok(petschaft_agent::sign_response(signed.signature()))
    }

    fn device_sign(&self, request: SignRequest) -> Result<SignedIdentity, String> {
        let (reply, rx) = mpsc::channel();
        let job = Job {
            request,
            queued: Instant::now(),
            reply,
        };
        match self.jobs.try_send(job) {
            Ok(()) => {}
            // Only after clients gave up waiting (see below) while the device hangs.
            Err(TrySendError::Full(_)) => return Err("the device queue is full".to_owned()),
            Err(TrySendError::Disconnected(_)) => return Err(self.worker_died()),
        }
        match rx.recv_timeout(self.limits.max_reply_wait) {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "no answer from the device within {} s",
                self.limits.max_reply_wait.as_secs()
            )),
            Err(RecvTimeoutError::Disconnected) => Err(self.worker_died()),
        }
    }

    fn worker_died(&self) -> String {
        (self.limits.on_worker_death)();
        "the device worker stopped".to_owned()
    }
}

fn device_worker(mut open: SignerFactory, jobs: &mpsc::Receiver<Job>, max_wait: Duration) {
    let mut signer: Option<Box<dyn Signer>> = None;
    while let Ok(job) = jobs.recv() {
        let result = if job.queued.elapsed() > max_wait {
            Err(JobError::Stale(max_wait.as_secs()))
        } else {
            sign_with(&mut open, &mut signer, &job.request).map_err(JobError::Device)
        };
        // The client may have gone away meanwhile; nothing to do then.
        let _ = job.reply.send(result);
    }
}

/// Sign with the current connection, opening one if there is none. Any error drops
/// the connection (the helper may be closed or in an unknown state).
fn sign_with(
    open: &mut SignerFactory,
    signer: &mut Option<Box<dyn Signer>>,
    request: &SignRequest,
) -> Result<SignedIdentity, petschaft_device::Error> {
    let s = match signer {
        Some(s) => s,
        None => signer.insert(open()?),
    };
    let result = s.sign_identity(request);
    if result.is_err() {
        *signer = None;
    }
    result
}

/// A credential store whose calls run on a helper thread and give up after `timeout`
/// with an error, so a locked keychain or an unanswered Secret Service prompt cannot
/// block the device worker: `HelperSigner` then connects without a credential or skips
/// storing it, and the worker logs the warning. `open` runs on that thread as well
/// (opening the store may block too).
///
/// shortcut: a call that never returns keeps its thread; that costs one thread per
/// device connection attempt, which only happens after errors.
pub(crate) struct TimedStore<S> {
    pub(crate) open: fn() -> Result<S, StoreError>,
    pub(crate) timeout: Duration,
}

impl<S: CredentialStore + 'static> TimedStore<S> {
    fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(&S) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (tx, rx) = mpsc::channel();
        let open = self.open;
        std::thread::Builder::new()
            .name("pets-agent-keyring".into())
            .spawn(move || {
                let _ = tx.send(open().and_then(|s| op(&s)));
            })
            .map_err(|e| StoreError::Backend(format!("cannot start a thread: {e}")))?;
        rx.recv_timeout(self.timeout).unwrap_or_else(|_| {
            Err(StoreError::Backend(format!(
                "no answer within {} s",
                self.timeout.as_secs()
            )))
        })
    }
}

impl<S: CredentialStore + 'static> CredentialStore for TimedStore<S> {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        self.run(|s| s.load())
    }

    fn store(&self, credential: &Credential) -> Result<(), StoreError> {
        let credential = credential.clone();
        self.run(move |s| s.store(&credential))
    }

    fn delete(&self) -> Result<(), StoreError> {
        self.run(|s| s.delete())
    }
}

/// Per-connection state.
#[derive(Default)]
struct Connection {
    /// Verified `session-bind@openssh.com` bindings, in order.
    bindings: Vec<SessionBind>,
    /// Set by an invalid session-bind: all later signs are refused.
    tainted: bool,
}

/// Serve one client until EOF, an I/O or protocol error, the idle timeout or the end
/// of its lifetime ([`Limits::max_connection_time`]).
pub(crate) fn serve_client(agent: &Agent, stream: &UnixStream) {
    if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        return;
    }
    let deadline = Instant::now().checked_add(agent.limits.max_connection_time);
    let mut conn = Connection::default();
    let (mut reader, mut writer) = (stream, stream);
    loop {
        // Each read waits at most the idle timeout and never past the deadline.
        let left = deadline
            .and_then(|d| d.checked_duration_since(Instant::now()))
            .filter(|d| !d.is_zero());
        let Some(left) = left else {
            agent.log_noisy(&format!(
                "closing connection: open for more than {} s",
                agent.limits.max_connection_time.as_secs()
            ));
            return;
        };
        if stream
            .set_read_timeout(Some(left.min(IDLE_TIMEOUT)))
            .is_err()
        {
            return;
        }
        let body = match petschaft_agent::read_message(&mut reader) {
            Ok(Some(body)) => body,
            Ok(None) | Err(petschaft_agent::Error::Io(_)) => return,
            Err(e) => {
                agent.log_noisy(&format!("closing connection: {e}"));
                return;
            }
        };
        let reply = match parse_request(&body) {
            Ok(request) => match agent.handle(&mut conn, request) {
                Some(reply) => reply,
                None => return,
            },
            Err(e) => {
                agent.log_noisy(&format!("closing connection: {e}"));
                return;
            }
        };
        if petschaft_agent::write_message(&mut writer, &reply).is_err() {
            return;
        }
    }
}

/// Releases a client slot when the client thread ends (or is never started).
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn take_slot(active: &Arc<AtomicUsize>) -> Option<Slot> {
    active
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            if n < MAX_CLIENTS {
                n.checked_add(1)
            } else {
                None
            }
        })
        .ok()
        .map(|_| Slot(Arc::clone(active)))
}

/// The accept loop; runs until the process is terminated.
pub(crate) fn serve(listener: &UnixListener, agent: &Arc<Agent>) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log(&format!("accept failed: {e}"));
                // e.g. out of file descriptors: do not spin.
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        let Some(slot) = take_slot(&active) else {
            agent.log_noisy(&format!(
                "more than {MAX_CLIENTS} clients; connection refused"
            ));
            continue;
        };
        let agent = Arc::clone(agent);
        let spawned = std::thread::Builder::new()
            .name("pets-agent-client".into())
            .spawn(move || {
                let _slot = slot;
                serve_client(&agent, &stream);
            });
        if let Err(e) = spawned {
            log(&format!("cannot start a client thread: {e}"));
        }
    }
}

/// The daemon's [`Ui`]: no terminal, so it only logs.
pub(crate) struct DaemonUi;

impl Ui for DaemonUi {
    fn confirm_on_device(&self) {
        log("confirm on the Trezor ...");
    }

    fn pairing_code(&self) -> Result<String, petschaft_device::Error> {
        let msg = "the Trezor asks for pairing; run `pets pair` once in a terminal";
        log(msg);
        Err(petschaft_device::Error::Ui(msg.into()))
    }
}
