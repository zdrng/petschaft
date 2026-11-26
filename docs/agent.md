# `pets agent`: SSH agent design

`pets agent` is an SSH agent (draft-miller-ssh-agent / OpenSSH `PROTOCOL.agent`) that
serves **slip13** identities from the Trezor, over USB or Bluetooth. FIDO2 identities
never go through it (OpenSSH talks to the authenticator directly).

Goal: logging in with a Trezor key is as convenient as a normal agent, but a signature
is only ever produced for **the server the identity is pinned to**, after a confirmation
on the device that names the login.

## What the agent answers

| Request | Answer |
|---|---|
| `SSH_AGENTC_REQUEST_IDENTITIES` (11) | the public keys of identities that have `public_key` **and** `host_keys` configured |
| `SSH_AGENTC_SIGN_REQUEST` (13) | a signature, only if every rule below holds; otherwise `SSH_AGENT_FAILURE` |
| `SSH_AGENTC_EXTENSION` (27) `session-bind@openssh.com` | verified and recorded for this connection → `SSH_AGENT_SUCCESS` |
| everything else (add/remove/lock/unlock/other extensions) | `SSH_AGENT_FAILURE` |

## Config

```toml
[[identity]]
name = "desktop"
uri = "ssh://user@desktop"
curve = "ed25519"
passphrase = "standard"                           # "ask" (default) needs passphrase protection on the Trezor
public_key = "ssh-ed25519 AAAA…"                 # printed by `pets pubkey desktop`
fingerprint = "SHA256:…"                          # optional; if set, must match public_key
host_keys = ["SHA256:…"]                          # server host key fingerprints (ssh-keyscan | ssh-keygen -lf -)
```

`public_key` lets the agent list keys without touching the device. It must be a key of
the identity's `curve`; it also pins the key (the effective pin is `fingerprint` if set,
else the fingerprint of `public_key`; if both are set they must match). Its comment is
ignored (the identity's `comment` is used). `host_keys` is the list of server host keys
this identity may log in to: non-empty, no duplicates, at most 64, only for `ssh://`
identities that have a `public_key`. An identity without `host_keys` is not offered by
the agent at all (fail closed). fido2 identities reject both keys. Two slip13 identities
with the same key (same effective pin) are an error naming both.

Get the host key fingerprint of a server (verify it out of band, e.g. on the server
with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`):

```bash
ssh-keyscan -t ed25519 desktop | ssh-keygen -lf -
```

The config is read once when the agent starts: **restart the agent after changing it**.

## Signing rules (all must hold)

1. The connection sent a valid `session-bind@openssh.com` (OpenSSH ≥ 8.9 does this
   automatically). The agent verifies the host key's signature over the session
   identifier. Supported host key types: `ssh-ed25519`, `ecdsa-sha2-nistp256`; other
   types are refused with a log message (servers almost always offer ed25519).
2. `is_forwarding` of every binding on this connection is false: forwarded agents
   (`ssh -A`) are refused, so a compromised server cannot use the key.
   This detection relies on the forwarding client sending a `session-bind` with
   `is_forwarding` set, which OpenSSH ≥ 8.9 does for `ssh -A`. A raw forward of the
   socket (`ssh -R` of the socket path, socat, old clients) looks like a local client
   and **cannot be detected**: never forward the agent socket. Rule 3 still limits such
   a forward to logins into the pinned hosts.
3. The data is an SSH userauth request (`string session_id, byte 50, string user,
   string "ssh-connection", string "publickey", bool TRUE, string algorithm,
   string public key`), parsed strictly with every length checked:
   - `session_id` equals the **last** binding's session identifier (and, for
     OpenSSH's `publickey-hostbound-v00@openssh.com`, the server host key in the
     request equals the bound host key),
   - the algorithm equals the identity key's type,
   - the public key equals the requested identity's `public_key`,
   - the bound host key's fingerprint is in the identity's `host_keys`.
   Data starting with `SSHSIG` (git or file signatures) or anything else is refused.
4. The device signs through `petschaft-device` with `challenge_visual`
   `"ssh login <user> (<identity>) <host>"`, where `<host>` is the first 8 characters
   after `SHA256:` of the bound host key's fingerprint (compare with `ssh-keygen -lf`);
   the returned signature is verified and checked against the pin as for every other
   signature.

The remote **login user is not restricted** by the identity: any user name on a pinned
host can be signed for. `host_keys` is the boundary; the device prompt shows the user
name, so check it before confirming.

Signature encoding: `string "ssh-ed25519", string sig64` or
`string "ecdsa-sha2-nistp256", string(mpint r, mpint s)`.

## Process model

- One accept loop; one thread per client connection. At most 16 concurrent clients:
  a 17th connection is closed immediately. Messages ≤ 256 KiB; an oversized, empty or
  malformed message closes the connection. A client that sends nothing for 120 s is
  disconnected; replies time out after 10 s. Every connection is closed 10 min after
  it was opened, whatever it sends (ssh uses one connection per authentication), so a
  client that keeps sending other requests cannot hold a slot forever.
- Per connection: the list of verified session bindings (at most 16, like OpenSSH;
  one more closes the connection). An invalid `session-bind` (bad signature,
  unsupported host key type) **taints** the connection: every later sign request on it
  is refused, also after further valid bindings.
- One device worker thread owns the `HelperSigner`; sign requests are serialized
  through a bounded channel. The connection is opened lazily on the first signature
  and dropped after any error (including a cancel on the device), so the next request
  opens a fresh one. The returned key is checked against the configured `public_key`
  (in `petschaft-device` through the pin, and again in the daemon).
- A sign request that waited more than 30 s in the queue (behind another confirmation
  on the device) is dropped with `SSH_AGENT_FAILURE` and a log line, instead of
  appearing on the device long after ssh gave up.
- A client waits at most 460 s for the device worker's answer (queue, opening the
  connection and signing with the helper's 180 s deadline each, two credential store
  calls, a margin), then gets `SSH_AGENT_FAILURE`, so a hung device cannot hold its
  connection; while the device hangs, further requests that find the queue full fail
  at once. Each call of the OS secret store from the worker runs on a helper thread
  and is given up after 30 s (a locked keychain, an unanswered prompt): the agent then
  connects without the stored credential or skips storing it, and logs a warning.
- If the device worker is gone (only after a panic), the agent logs it and exits with
  status 1, so systemd / launchd restart it. Release builds use `panic = "abort"`: any
  panic ends the process.
- Logging: one line per event on stderr (journal / launchd log): at start the config
  file and the offered identities, then sign requests, signatures, denials with their
  reason, invalid bindings, device connections. Lines a client can cause without the
  device (denials, invalid bindings, protocol errors, refused or expired connections)
  are rate limited to 10 per minute; the number suppressed is logged with the next such
  line after the minute. No secrets; the remote user name is escaped (only ASCII graphic characters are kept,
  everything else becomes `\u{..}`, cut to 32 characters) for the log and the device.
- The agent cannot ask for a pairing code (no terminal): if the device needs pairing
  the request fails with a log message telling the user to run `pets pair` once.
- Socket: Linux `$XDG_RUNTIME_DIR/petschaft/agent.sock` (error if `XDG_RUNTIME_DIR` is
  unset), macOS `~/Library/Application Support/petschaft/agent.sock`; `--socket <path>`
  overrides it (absolute path). The directory is created with 0700 if missing; an
  existing one is refused if it is a symlink, not owned by us, or accessible by group or
  others (so `--socket /tmp/x.sock` is refused). The socket gets 0600. Other users
  cannot reach it because of the directory permissions (OpenSSH's own agent relies on
  the same property; the peer uid is not checked separately).
- Shutdown: std cannot catch SIGTERM/SIGINT without `unsafe` (forbidden in this
  workspace), so the agent simply terminates and the socket file stays behind. On the
  next start an existing `agent.sock` is replaced only if it is a socket owned by us
  that nobody listens on; a socket another agent listens on, or anything that is not a
  socket, is an error and left untouched. The systemd unit additionally removes the
  directory when the service stops (`RuntimeDirectory`).
- Use it per host, not globally (Linux: `${XDG_RUNTIME_DIR}` is expanded by ssh):
  ```
  Host desktop
    IdentityAgent ~/Library/Application\ Support/petschaft/agent.sock
    IdentitiesOnly yes

  Host homelab
    IdentityAgent ${XDG_RUNTIME_DIR}/petschaft/agent.sock
    IdentitiesOnly yes
  ```

## Commands

- `pets agent [--socket <path>]`: run in the foreground (services start this).
- `pets pair`: connect once from a terminal, enter the pairing code if the Trezor asks
  for one, store the credential in the OS secret store and print the device info. No
  signature is made. Do this once before using the agent: the agent has no terminal and
  fails a request with "run `pets pair`" if the device wants to pair.
- `pets pubkey <name>`: prints the key; if `public_key` is not configured yet, also
  the exact `public_key = "…"` line to paste into the identity (stderr).

## Setup

1. `pets pubkey desktop` → paste the printed `public_key = "…"` line into the identity.
2. `ssh-keyscan -t ed25519 desktop | ssh-keygen -lf -` → put the `SHA256:…` into
   `host_keys` (after checking it).
3. `pets pair` once.
4. Start the agent (service, or `pets agent` in a terminal) and add the `Host` block.

## Service integration

- NixOS: `programs.petschaft.agent.enable` → systemd user service `petschaft-agent`
  (see `docs/nix.md` for the hardening).
- nix-darwin: `programs.petschaft.agent.enable` → `launchd.user.agents.petschaft-agent`
  (log: `~/Library/Logs/petschaft-agent.log` unless `agent.logFile` is set; rotated at
  agent start above 1 MiB, 3 old files kept).
- macOS Keychain: the credential stored by `pets pair` belongs to the `pets` binary
  that stored it; after an upgrade (new store path) macOS may ask once whether the new
  binary may use it.

## Not tested automatically

Everything above is tested with a software signer over the real socket
(`crates/petschaft/src/agent/tests.rs`). Not covered: a real Trezor, real `ssh`
against the socket, the systemd/launchd units at runtime (only evaluated).
