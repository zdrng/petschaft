//! petschaft command line: public keys, pairing management, git and APK signing and the
//! SSH agent.

#![forbid(unsafe_code)]

mod agent;
mod apk;
mod fido2;
mod git;

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use petschaft_core::{Config, IdentityConfig};
use petschaft_device::{
    ConnectOptions, CredentialStore, HelperPaths, HelperSigner, KeyringStore, NoStore, SignRequest,
    Signer, Ui,
};

#[derive(Parser)]
#[command(
    name = "pets",
    version,
    about = "SSH, git and APK signing with a Trezor"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// `--config`, on every subcommand that reads the config (not on `forget` and
/// `apk verify`, which never do).
#[derive(Args)]
struct ConfigArg {
    /// Config file (default: $XDG_CONFIG_HOME/petschaft/config.toml or
    /// ~/.config/petschaft/config.toml if it exists, else /etc/petschaft/config.toml)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// List configured identities (no device needed)
    List {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Show the OpenSSH public key of an identity (one confirmation on the Trezor)
    Pubkey {
        /// Identity name from the config
        name: String,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Delete the stored Trezor pairing credential from the OS secret store
    Forget,
    /// Pair with the Trezor once from a terminal (pairing code) and store the credential
    Pair {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Run the SSH agent in the foreground (slip13 identities with public_key and host_keys)
    Agent {
        /// Socket path (default: $XDG_RUNTIME_DIR/petschaft/agent.sock on Linux,
        /// ~/Library/Application Support/petschaft/agent.sock on macOS); its
        /// directory must be private (0700)
        #[arg(long)]
        socket: Option<PathBuf>,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// FIDO2 (hardware-only, USB) keys
    #[command(subcommand)]
    Fido2(Fido2Command),
    /// SSH with a fido2 identity's key (FIDO-capable OpenSSH, USB): pets ssh <name> -- <ssh args>
    Ssh {
        /// fido2 identity name from the config
        name: String,
        /// Arguments passed to ssh (after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Print authorized_keys lines and an sshd drop-in for fido2 identities (all if none given)
    SshdConfig {
        /// fido2 identity names from the config (default: all)
        names: Vec<String>,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Android APK signing (APK Signature Scheme v2/v3) with a gpg:// nist256p1 identity
    #[command(subcommand)]
    Apk(ApkCommand),
}

#[derive(Subcommand)]
enum ApkCommand {
    /// Create the identity's self-signed certificate (two confirmations on the Trezor)
    /// and print the `certificate = "..."` config line
    Init {
        /// APK identity name from the config (gpg:// uri, curve nist256p1)
        name: String,
        /// Certificate subject: "CN=<name>" or just the name (1-64 printable ASCII)
        #[arg(long)]
        subject: String,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Sign an APK with v2 and v3 signatures (two confirmations on the Trezor, showing
    /// package:versionName(versionCode) read with aapt2); the result is verified with
    /// apksigner before it is written to -o, which must not exist. Only for apps with
    /// minSdkVersion >= 24 (no v1 signatures; others are refused)
    Sign {
        /// APK identity name from the config (with certificate and fingerprint)
        name: String,
        /// The (unsigned) APK, at most 256 MiB
        input: PathBuf,
        /// Output file (never overwritten)
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Remove an existing APK Signing Block (re-sign)
        #[arg(long)]
        replace: bool,
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Verify an APK with apksigner (`apksigner verify -v --print-certs`; no config, no
    /// device)
    Verify {
        /// The APK to verify
        apk: PathBuf,
        /// Check for this minSdkVersion
        #[arg(long)]
        min_sdk: Option<u32>,
    },
}

#[derive(Subcommand)]
enum Fido2Command {
    /// Create the FIDO2 key of a fido2 identity on the Trezor (USB; touch and PIN on the device)
    Create {
        /// fido2 identity name from the config
        name: String,
        /// Use this authenticator device (only needed with several attached)
        #[arg(long)]
        device: Option<PathBuf>,
        #[command(flatten)]
        config: ConfigArg,
    },
}

fn main() -> ExitCode {
    // git calls `gpg.ssh.program` like ssh-keygen: `pets -Y sign ...`.
    let args: Vec<OsString> = std::env::args_os().collect();
    if let Some(rest) = args
        .get(1..)
        .filter(|r| r.first().is_some_and(|a| a == "-Y"))
    {
        return git::ssh_keygen_compat(rest);
    }
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pets: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Forget => forget(),
        Command::List { config } => list(&load_config(config.config)?),
        Command::Pubkey { name, config } => {
            let config = load_config(config.config)?;
            match config.find(&name) {
                Some(IdentityConfig::Fido2(f)) => fido2::pubkey(&fido2::key_dir()?, f),
                _ => pubkey(&config, &name),
            }
        }
        Command::Fido2(Fido2Command::Create {
            name,
            device,
            config,
        }) => fido2::create(
            &load_config(config.config)?,
            &fido2::key_dir()?,
            &name,
            device,
        ),
        Command::Ssh { name, args, config } => fido2::ssh(
            &load_config(config.config)?,
            &fido2::key_dir()?,
            &name,
            &args,
        ),
        Command::SshdConfig { names, config } => {
            fido2::sshd_config(&load_config(config.config)?, &fido2::key_dir()?, &names)
        }
        Command::Pair { config } => pair(&load_config(config.config)?),
        Command::Agent { socket, config } => {
            let config_file = config_path(config.config)?;
            let config = load_config(Some(config_file.clone()))?;
            run_agent(&config, &config_file, socket)
        }
        Command::Apk(cmd) => run_apk(cmd),
    }
}

fn run_apk(cmd: ApkCommand) -> Result<()> {
    match cmd {
        ApkCommand::Init {
            name,
            subject,
            config,
        } => {
            let config = load_config(config.config)?;
            let id = config.slip13(&name)?;
            let cert = apk::init(id, &subject, || connect(&config))?;
            apk::print_init(id, &cert)
        }
        ApkCommand::Sign {
            name,
            input,
            output,
            replace,
            config,
        } => {
            let config = load_config(config.config)?;
            let id = config.slip13(&name)?;
            let args = apk::SignArgs {
                input,
                output,
                replace,
            };
            // Resolved (and checked in `sign`) before anything else: no confirmation on
            // the device without the manifest reader and a verifier for the result.
            let tools = apk::Tools {
                apksigner: apk::apksigner_path()?,
                aapt2: apk::aapt2_path()?,
            };
            let report = apk::sign(id, &args, &tools, || connect(&config))?;
            apk::print_sign(&args, &report);
            Ok(())
        }
        // Needs no config and no device.
        ApkCommand::Verify { apk, min_sdk } => apk::verify(&apk::apksigner_path()?, &apk, min_sdk),
    }
}

/// `--config` if given, else the per-user or the system config ([`Config::locate`]).
fn config_path(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(p) => Ok(p),
        None => Config::locate().map_err(|e| anyhow!("{e}; create one or pass --config <file>")),
    }
}

/// Errors of [`Config::load`] already name the file: no context added here.
pub(crate) fn load_config(path: Option<PathBuf>) -> Result<Config> {
    Ok(Config::load(&config_path(path)?)?)
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn list(config: &Config) -> Result<()> {
    if config.identities().is_empty() {
        eprintln!("no identities configured");
    }
    for id in config.identities() {
        let pin = id
            .fingerprint()
            .map_or_else(|| "(not pinned)".to_owned(), ToString::to_string);
        // The comment goes last: it is the only field that may contain spaces.
        let comment = id.comment();
        match id {
            IdentityConfig::Slip13(s) => println!(
                "{:<16} {:<6} {:<40} {:<10} passphrase={:<8} {pin:<50} {}comment: {comment}",
                s.name(),
                id.kind(),
                s.identity().to_uri(),
                s.curve().as_str(),
                s.passphrase().as_str(),
                s.certificate().map_or_else(String::new, |c| format!(
                    "apk-cert={} ",
                    apk::colon_hex(&c.sha256_fingerprint())
                )),
            ),
            IdentityConfig::Fido2(f) => println!(
                "{:<16} {:<6} {:<40} {:<10} verify-required={:<3} resident={:<3} {pin:<50} comment: {comment}",
                f.name(),
                id.kind(),
                f.application(),
                f.algorithm(),
                yes_no(f.user_verification()),
                yes_no(f.resident()),
            ),
        }
    }
    Ok(())
}

fn pubkey(config: &Config, name: &str) -> Result<()> {
    let id = config.slip13(name)?;
    let mut signer = connect(config)?;

    // Fresh random challenge: the device proves possession of the key it reports.
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| anyhow!("no system randomness: {e}"))?;
    let req = SignRequest::for_identity(
        id,
        challenge.to_vec(),
        format!("pets: public key {}", id.name()),
    );
    let signed = signer.sign_identity(&req)?;
    let key = signed.public_key();

    println!("{}", key.openssh_line(id.comment().as_str()));
    eprintln!("fingerprint: {}", key.fingerprint());
    if id.fingerprint().is_none() {
        eprintln!(
            "not pinned yet: add  fingerprint = \"{}\"  to [[identity]] \"{}\" in the config",
            key.fingerprint(),
            id.name()
        );
    } else {
        eprintln!("matches the pinned fingerprint");
    }
    if id.public_key().is_none() {
        // Without a comment: the line is base64 and a key type only, so it is always a
        // valid TOML string (the comment comes from the config).
        eprintln!(
            "for `pets agent` (also pins the key), add to [[identity]] \"{}\":",
            id.name()
        );
        eprintln!("public_key = \"{}\"", key.openssh_line(""));
    }
    Ok(())
}

/// `pets pair`: connect once from a terminal (the pairing code is asked for there if
/// the Trezor needs it) and store the credential. No signature is made.
fn pair(config: &Config) -> Result<()> {
    let (signer, secure) = connect_with(config, TerminalUi)?;
    let d = signer.device();
    eprintln!(
        "passphrase protection: {}",
        if d.passphrase_protection { "on" } else { "off" }
    );
    match (secure, signer.store_warning()) {
        (true, None) => eprintln!(
            "the pairing credential is stored in the OS secret store; \
             `pets agent` and other commands connect without a pairing code"
        ),
        (true, Some(_)) | (false, _) => {
            bail!("the pairing credential could not be stored (see the warning above)")
        }
    }
    Ok(())
}

/// `pets agent`: read the config once, bind the socket and serve until terminated.
fn run_agent(config: &Config, config_file: &Path, socket: Option<PathBuf>) -> Result<()> {
    let (keys, notes) = agent::agent_keys(config);
    agent::log(&agent::startup_summary(config_file, &keys));
    for n in &notes {
        agent::log(n);
    }
    if keys.is_empty() {
        agent::log(
            "warning: no identity is offered (each needs public_key and host_keys); \
             every request will be refused",
        );
    }
    let paths = HelperPaths::resolve()?;
    let options = ConnectOptions::new(host_name(), config.transport());
    let open: agent::SignerFactory = Box::new(move || {
        let store = agent::TimedStore {
            open: KeyringStore::new,
            timeout: agent::KEYRING_TIMEOUT,
        };
        let signer = HelperSigner::spawn(&paths, &options, agent::DaemonUi, &store)?;
        if let Some(w) = signer.store_warning() {
            agent::log(&format!(
                "warning: pairing credential not loaded or stored: {w}"
            ));
        }
        let d = signer.device();
        agent::log(&format!(
            "connected: {} ({}), firmware {}",
            d.model, d.internal_model, d.firmware
        ));
        Ok(Box::new(signer) as Box<dyn Signer>)
    });
    let path = match socket {
        Some(p) => p,
        None => agent::default_socket_path()?,
    };
    let listener = agent::bind(&path)?;
    let agent = Arc::new(agent::Agent::new(keys, open).context("cannot start the device worker")?);
    agent::log(&format!(
        "listening on {} (config is read only at start: restart after changing it)",
        path.display()
    ));
    agent::serve(&listener, &agent);
    Ok(())
}

fn forget() -> Result<()> {
    KeyringStore::new()
        .map_err(|e| anyhow!("{e}"))?
        .delete()
        .map_err(|e| anyhow!("{e}"))?;
    eprintln!(
        "pairing credential deleted from this computer; the next connection asks for a pairing code"
    );
    eprintln!("note: the Trezor itself can only revoke all pairings at once (device settings)");
    Ok(())
}

pub(crate) fn connect(config: &Config) -> Result<HelperSigner<TerminalUi>> {
    connect_with(config, TerminalUi).map(|(signer, _)| signer)
}

/// Connect with `ui`; the flag tells whether a secure credential store was used.
fn connect_with<U: Ui>(config: &Config, ui: U) -> Result<(HelperSigner<U>, bool)> {
    let paths = HelperPaths::resolve()?;
    let options = ConnectOptions::new(host_name(), config.transport());
    // Secure store or nothing: never a plaintext fallback.
    let keyring;
    let (store, secure): (&dyn CredentialStore, bool) = match KeyringStore::new() {
        Ok(k) => {
            keyring = k;
            (&keyring, true)
        }
        Err(e) => {
            eprintln!(
                "warning: no secure credential store ({e}); pairing will be needed every time"
            );
            (&NoStore, false)
        }
    };
    let signer = HelperSigner::spawn(&paths, &options, ui, store)?;
    if let Some(w) = signer.store_warning() {
        eprintln!("warning: pairing credential not persisted: {w}");
    }
    let d = signer.device();
    say(&format!(
        "connected: {} ({}), firmware {}",
        d.model, d.internal_model, d.firmware
    ));
    Ok((signer, secure))
}

/// Status line for the user: on the terminal if there is one (git captures the signing
/// program's stderr and only shows it on failure), otherwise on stderr.
pub(crate) fn say(msg: &str) {
    match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(mut tty) => {
            let _ = writeln!(tty, "{msg}");
        }
        Err(_) => eprintln!("{msg}"),
    }
}

/// Shown on the Trezor during pairing; must be 1-64 characters of 0x21-0x7E.
fn host_name() -> String {
    format!("petschaft-{}", std::env::consts::OS)
}

/// Prompts on the controlling terminal (not stdin/stdout, which may be redirected).
struct TerminalUi;

impl Ui for TerminalUi {
    fn confirm_on_device(&self) {
        say("  -> confirm on the Trezor ...");
    }

    fn pairing_code(&self) -> Result<String, petschaft_device::Error> {
        let ui_err = |e: std::io::Error| petschaft_device::Error::Ui(e.to_string());
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(ui_err)?;
        let mut out = &tty;
        write!(out, "  Pairing code shown on the Trezor: ").map_err(ui_err)?;
        out.flush().map_err(ui_err)?;
        let mut line = String::new();
        // Bounded read: a pairing code is 6 digits.
        BufReader::new(&tty)
            .take(64)
            .read_line(&mut line)
            .map_err(ui_err)?;
        Ok(line.trim().to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pets").chain(args.iter().copied()))
    }

    #[test]
    fn cli_definition() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_positional_argument_has_help() {
        fn walk(cmd: &clap::Command, path: &str) {
            for arg in cmd.get_positionals() {
                assert!(
                    arg.get_help().is_some(),
                    "{path} <{}> has no help",
                    arg.get_id()
                );
            }
            for sub in cmd.get_subcommands() {
                walk(sub, &format!("{path} {}", sub.get_name()));
            }
        }
        walk(&Cli::command(), "pets");
    }

    #[test]
    fn config_only_where_it_is_read() {
        assert!(parse(&["apk", "verify", "--config", "c", "x.apk"]).is_err());
        assert!(parse(&["forget", "--config", "c"]).is_err());
        let Command::Apk(ApkCommand::Verify { apk, min_sdk }) =
            parse(&["apk", "verify", "x.apk"]).unwrap().command
        else {
            panic!("apk verify");
        };
        assert_eq!((apk, min_sdk), (PathBuf::from("x.apk"), None));
        let Command::Apk(ApkCommand::Sign { config, .. }) = parse(&[
            "apk", "sign", "--config", "c", "n", "in.apk", "-o", "out.apk",
        ])
        .unwrap()
        .command
        else {
            panic!("apk sign");
        };
        assert_eq!(config.config, Some(PathBuf::from("c")));
        // Everything after the name belongs to ssh.
        let Command::Ssh { name, args, config } =
            parse(&["ssh", "--config", "c", "host", "--", "-p", "22", "--config"])
                .unwrap()
                .command
        else {
            panic!("ssh");
        };
        assert_eq!((name.as_str(), config.config), ("host", Some("c".into())));
        assert_eq!(args, ["-p", "22", "--config"]);
    }

    #[test]
    fn apk_sign_has_no_min_sdk() {
        assert!(
            parse(&[
                "apk",
                "sign",
                "--min-sdk",
                "24",
                "n",
                "in.apk",
                "-o",
                "o.apk"
            ])
            .is_err()
        );
        let Command::Apk(ApkCommand::Sign {
            name,
            input,
            output,
            replace,
            config,
        }) = parse(&["apk", "sign", "n", "in.apk", "-o", "o.apk", "--replace"])
            .unwrap()
            .command
        else {
            panic!("apk sign");
        };
        assert_eq!(
            (name.as_str(), input, output, replace, config.config),
            ("n", "in.apk".into(), "o.apk".into(), true, None)
        );
    }

    /// The config path appears once in an error, not again as context.
    #[test]
    fn config_errors_name_the_file_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(&p, "transport = \"carrier pigeon\"\n").unwrap();
        let e = format!("{:#}", load_config(Some(p.clone())).unwrap_err());
        assert_eq!(e.matches(&*p.to_string_lossy()).count(), 1, "{e}");
        assert!(e.starts_with("invalid config: "), "{e}");
    }
}
