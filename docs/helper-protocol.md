# petschaft helper protocol (version 1)

The Rust side (`petschaft-device`) talks to the Trezor through a small Python helper
(`helper/petschaft_helper.py`, official `trezorlib`) running as a child process. This file is
the contract between the two. Both sides validate strictly and reject anything not
described here.

## Process model

- Rust spawns `python3 -I -B helper/petschaft_helper.py` (isolated mode, no bytecode cache writes) with stdin/stdout as pipes and stderr
  inherited (diagnostics only, never secrets).
- One helper process serves one Rust client. Requests are strictly sequential: the host
  sends the next request only after the final response (`ready`, `signed` or `error`)
  to the previous one.
- Closing stdin (EOF) ends the helper; it exits with status 0. After sending an `error`
  with `fatal: true` the helper exits with status 1.
- The helper writes nothing to disk, opens no network connections and keeps no state
  beyond the open device connection and sessions.
- Everything the helper or `trezorlib` might print must not reach stdout: the helper
  keeps the original stdout file descriptor for frames and points `sys.stdout` at
  stderr before importing `trezorlib`.

## Framing

Each message is one frame: a 4-byte big-endian unsigned length `n`, then `n` bytes of
UTF-8 JSON encoding exactly one object. `1 <= n <= 65536`; a larger or zero length,
invalid UTF-8, invalid JSON or a non-object is a protocol error (receiver aborts).

Binary fields are standard base64 with padding (RFC 4648 §4). Unknown fields and
unknown `type` values are rejected. Strings are validated as noted; "token" means
1-128 printable ASCII characters (0x21-0x7E) without `/`, `@`, `:`.

## Common objects

**identity**

```json
{"proto": "ssh", "user": "demo", "host": "homelab", "port": null, "path": null, "index": 0}
```

| field | rule |
|---|---|
| `proto` | `"ssh"` or `"gpg"` |
| `user` | token or `null` |
| `host` | token (required) |
| `port` | 1-5 ASCII digits or `null` |
| `path` | `null` or 1-128 printable ASCII characters starting with `/`, no `@` |
| `index` | integer 0 … 2^32−1 |

Mapped 1:1 onto trezorlib `messages.IdentityType`.

## Host → helper

### `hello` (first message, exactly once)

```json
{"type": "hello", "version": 1, "app_name": "petschaft", "host_name": "mac",
 "transport": "auto", "credential": "<base64>" }
```

- `version`: must be `1`.
- `app_name`, `host_name`: 1-64 printable ASCII characters; shown on the Trezor during
  pairing.
- `transport`: `"usb"` (WebUSB only), `"ble"` (Bluetooth only) or `"auto"` (USB if a
  device is present, otherwise Bluetooth). If more than one Trezor is found on the
  chosen transport, the helper does not pick one: it answers `error` `device_error`
  (fatal) "more than one Trezor found; connect only one". A device that does not speak
  THP (protocol v1) is likewise a fatal `device_error`.
- `credential`: `null`, or an opaque blob previously returned in `ready.credential`.
  The host never interprets it. Maximum decoded size 4096 bytes.

### `pairing_code` (only in reply to event `pairing_code_required`)

```json
{"type": "pairing_code", "code": "620567"}
```

`code`: exactly 6 ASCII digits.

### `sign_identity`

```json
{"type": "sign_identity", "id": 1, "identity": { ... }, "curve": "ed25519",
 "challenge_hidden": "<base64>", "challenge_visual": "pets: Login homelab",
 "passphrase": "standard"}
```

- `id`: integer 1 … 2^32−1, echoed in the response.
- `curve`: `"ed25519"` or `"nist256p1"`.
- `challenge_hidden`: 0-512 decoded bytes. For `proto = "gpg"` with `nist256p1` it must
  be exactly 32 bytes (a SHA-256 digest).
- `challenge_visual`: 0-128 printable characters (Unicode allowed, no control
  characters). Shown on the Trezor display.
- `passphrase`: `"standard"` → standard wallet (empty passphrase), no prompt; the
  helper may reuse one standard session. `"ask"` → a new session with the passphrase
  entered on the device, every time. If the device has passphrase protection disabled,
  `"ask"` fails with `passphrase_unavailable`.

## Helper → host

### `event` (zero or more, before a final response)

```json
{"type": "event", "event": "button"}
```

- `button`: the Trezor is waiting for a confirmation on its display.
- `pairing_code_required`: the Trezor shows a pairing code; the host must reply with
  `pairing_code`.

### `ready` (final response to `hello`)

```json
{"type": "ready",
 "device": {"model": "Safe 7", "internal_model": "T3W1", "firmware": "2.13.1",
            "passphrase_protection": true},
 "credential": "<base64>"}
```

`credential` is non-null only when a new pairing credential was issued in this
connection (after code-entry pairing; never an autoconnect credential). The host
stores it securely and passes it in future `hello` messages. If the device is not
initialized, the helper answers `error` `device_not_initialized` instead.

### `signed` (final response to `sign_identity`)

```json
{"type": "signed", "id": 1, "public_key": "<base64>", "signature": "<base64>"}
```

Raw `SignedIdentity.public_key` and `SignedIdentity.signature` as returned by the
device (ed25519: 33-byte key with leading 0x00, 65-byte signature with leading 0x00;
nist256p1: 33-byte compressed key, 65-byte signature `0x00 || r || s`). The helper does
not interpret them; the Rust side validates and verifies.

### `error` (final response)

```json
{"type": "error", "id": 1, "code": "cancelled", "message": "rejected on device", "fatal": false}
```

- `id`: the request id, or `null` for `hello`/protocol errors.
- `code`: one of `bad_request`, `device_not_found`, `device_not_initialized`,
  `pairing_failed`, `cancelled`, `passphrase_unavailable`, `device_error`, `internal`.
- `message`: ≤ 256 characters, human-readable, never contains secrets.
- `fatal`: `true` if the helper exits afterwards. `bad_request`, `device_not_found`,
  `device_not_initialized`, `pairing_failed` and `internal` are always fatal.

## Timeouts

The helper imposes none (user confirmations can take long). The host enforces them:
120 s for `hello` until the first event or `ready` (covers BLE discovery, PIN entry
and the OS Bluetooth pairing dialog, which produce no event), 180 s per request overall; on
timeout it kills the helper.
