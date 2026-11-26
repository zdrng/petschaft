//! Server-side configuration text for hardware-only SSH login.

use crate::{PublicKeyLine, SkAlgorithm};

/// Path of the recommended `sshd` drop-in.
pub const SSHD_DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/10-petschaft.conf";

/// The `authorized_keys` line for `key`: `verify-required ` prefixed when requested.
///
/// Never emits `no-touch-required`: user presence is always required.
pub fn authorized_keys_line(key: &PublicKeyLine, verify_required: bool) -> String {
    if verify_required {
        format!("verify-required {}", key.to_line())
    } else {
        key.to_line()
    }
}

/// Text for the server administrator: (a) an `authorized_keys` block for `keys`
/// (`verify_required` per key), (b) the recommended `sshd` drop-in that accepts only
/// security-key public keys. `verify_required` must match how the key was created
/// (`-O verify-required`), otherwise login fails because the authenticator did not
/// verify the user.
pub fn sshd_snippet(keys: &[(&PublicKeyLine, bool)]) -> String {
    let algorithms = SkAlgorithm::ALL.map(SkAlgorithm::ssh_name).join(",");
    let mut out = String::from(
        "# --- ~/.ssh/authorized_keys on the server (append) ---\n\
         # sk-* keys: the private key never leaves the authenticator; every login needs\n\
         # a touch, and \"verify-required\" additionally the PIN.\n",
    );
    for (key, verify_required) in keys {
        out.push_str(&authorized_keys_line(key, *verify_required));
        out.push('\n');
    }
    out.push_str(&format!(
        "\n# --- {SSHD_DROPIN_PATH} ---\n\
         # Accept only hardware (FIDO2 security key) public keys; no passwords.\n\
         #\n\
         # Server requirements: OpenSSH >= 8.5 (sk keys need 8.2, verify-required 8.4,\n\
         # PubkeyAcceptedAlgorithms 8.5). Check with: ssh -V\n\
         #\n\
         # sshd uses the FIRST value it reads for each keyword. Drop-ins are read in\n\
         # lexical order where /etc/ssh/sshd_config includes sshd_config.d/*.conf (usually\n\
         # at its top), so a lower-numbered drop-in or an earlier line in sshd_config\n\
         # wins over this file. Make sure the Include exists:\n\
         #   grep -n Include /etc/ssh/sshd_config\n\
         # Match blocks override these values for matching users; check the effective\n\
         # values for your login:  sudo sshd -T -C user=$USER,host=x,addr=127.0.0.1\n\
         # This applies to every account on this sshd (deploy/backup users, git hosting):\n\
         # to restrict only yourself, put the lines under  Match User <you>  instead.\n\
         #\n\
         # Before reloading sshd, validate the configuration:      sudo sshd -t\n\
         # Keep your current session open and test the login in a SECOND session before\n\
         # closing the first, so a mistake cannot lock you out.\n\
         PubkeyAcceptedAlgorithms {algorithms}\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         AuthenticationMethods publickey\n\
         # Recommended unless you log in as root (then this would lock you out):\n\
         # PermitRootLogin no\n\
         # Optional: require PIN verification for every sk key, server-wide.\n\
         # PubkeyAuthOptions verify-required\n"
    ));
    out
}
