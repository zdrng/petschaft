"""petschaft helper: the only petschaft process that talks to the Trezor (through trezorlib).

Implements docs/helper-protocol.md, version 1, and nothing else. Frames are read from
stdin and written to a private duplicate of the original stdout; anything else that is
printed (trezorlib, bleak, child processes) can only reach stderr. No files, no network,
no state beyond the open device connection and its sessions.

Run as: python3 -I -B helper/petschaft_helper.py
"""

from __future__ import annotations

import atexit
import base64
import binascii
import json
import logging
import multiprocessing
import os
import resource
import signal
import struct
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, field
from typing import Any, BinaryIO

MAX_FRAME = 65536
MAX_CREDENTIAL = 4096
MAX_CHALLENGE = 512
MAX_VISUAL = 128
MAX_MESSAGE = 256
U32_MAX = 0xFFFF_FFFF
BLE_SCAN_TIMEOUT = 15.0  # seconds; the host allows 120 s for `hello` until the first frame
BLE_CONNECT_TIMEOUT = 30.0  # seconds, Linux only (trezorlib: 3 s); as Trezor Suite
# Markers in builtin exceptions, so that they survive the pipe from the BLE child process
# (an exception class of this module would not unpickle there: `__mp_main__` vs `__main__`).
BLE_NOT_PAIRED = "petschaft:ble-not-paired"
BLE_CONNECT_TIMED_OUT = "petschaft:ble-connect-timed-out"
BLUEZ_AUTH_ERRORS = frozenset(
    {
        "org.bluez.Error.AuthenticationFailed",
        "org.bluez.Error.AuthenticationCanceled",
        "org.bluez.Error.AuthenticationRejected",
        "org.bluez.Error.AuthenticationTimeout",
    }
)
ALWAYS_FATAL = frozenset(
    {"bad_request", "device_not_found", "device_not_initialized", "pairing_failed", "internal"}
)
DIGITS = frozenset("0123456789")


class HelperError(Exception):
    """An error reported to the host. `message` must never contain secrets."""

    def __init__(self, code: str, message: str, *, fatal: bool = False) -> None:
        super().__init__(code)
        self.code, self.message = code, message[:MAX_MESSAGE]
        self.fatal = fatal or code in ALWAYS_FATAL


def bad_request(message: str) -> HelperError:
    return HelperError("bad_request", message)


class EndOfInput(BaseException):  # BaseException: no `except Exception` may swallow it
    """stdin was closed at a frame boundary: exit with status 0."""


# ---- framing ---------------------------------------------------------------------------


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def _no_constant(_name: str) -> None:
    raise ValueError("NaN/Infinity are not JSON")


def read_frame(rx: BinaryIO) -> dict[str, Any]:
    header = rx.read(4)
    if not header:
        raise EndOfInput
    if len(header) != 4:
        raise bad_request("truncated frame header")
    (length,) = struct.unpack(">I", header)
    if not 1 <= length <= MAX_FRAME:
        raise bad_request("invalid frame length")
    body = rx.read(length)
    if body is None or len(body) != length:
        raise bad_request("truncated frame")
    try:
        obj = json.loads(
            body.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_no_constant
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise bad_request("frame is not valid UTF-8 JSON") from None
    if not isinstance(obj, dict):
        raise bad_request("frame is not a JSON object")
    return obj


def encode_frame(obj: dict[str, Any]) -> bytes:
    body = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if not 1 <= len(body) <= MAX_FRAME:
        raise HelperError("internal", "response too large")
    return struct.pack(">I", len(body)) + body


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---- validation ------------------------------------------------------------------------


def _fields(msg: dict[str, Any], *names: str) -> None:
    if set(msg) != {"type", *names}:
        raise bad_request(f"{msg['type']}: unknown or missing fields")


def _uint(value: Any, name: str, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:  # `type` excludes bool
        raise bad_request(f"{name}: integer {lo}..{hi} required")
    return value


def _choice(value: Any, name: str, choices: tuple[str, ...]) -> str:
    if type(value) is not str or value not in choices:
        raise bad_request(f"{name}: must be one of {', '.join(choices)}")
    return value


def _is_ascii(value: Any, max_len: int, forbidden: str = "", first: str = "!") -> bool:
    """1..max_len ASCII characters in first..0x7E, none of `forbidden`."""
    return (
        type(value) is str
        and 1 <= len(value) <= max_len
        and all(first <= c <= "~" and c not in forbidden for c in value)
    )


def _ascii(value: Any, name: str, max_len: int, forbidden: str = "") -> str:
    """1..max_len printable ASCII characters (0x21-0x7E), none of `forbidden`."""
    if not _is_ascii(value, max_len, forbidden):
        raise bad_request(f"{name}: 1-{max_len} printable ASCII characters required")
    return value


def _token(value: Any, name: str) -> str:
    return _ascii(value, name, 128, "/@:")


def _base64(value: Any, name: str, max_len: int) -> bytes:
    """Canonical standard base64 with padding, at most `max_len` decoded bytes."""
    if type(value) is not str or len(value) > 4 * ((max_len + 2) // 3):
        raise bad_request(f"{name}: base64 of at most {max_len} bytes required")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise bad_request(f"{name}: invalid base64") from None
    if len(data) > max_len or b64(data) != value:
        raise bad_request(f"{name}: invalid base64")
    return data


@dataclass(frozen=True)
class Hello:
    app_name: str
    host_name: str
    transport: str
    credential: bytes | None = field(repr=False)


@dataclass(frozen=True)
class SignRequest:
    id: int
    identity: dict[str, Any]  # validated; the fields of messages.IdentityType
    curve: str
    challenge_hidden: bytes = field(repr=False)
    challenge_visual: str = field(repr=False)
    passphrase: str


@dataclass(frozen=True)
class Ready:
    model: str
    internal_model: str
    firmware: str
    passphrase_protection: bool
    credential: bytes | None = field(default=None, repr=False)


def parse_hello(msg: dict[str, Any]) -> Hello:
    if msg.get("type") != "hello":
        raise bad_request("expected hello")
    _fields(msg, "version", "app_name", "host_name", "transport", "credential")
    if type(msg["version"]) is not int or msg["version"] != 1:
        raise bad_request("unsupported protocol version")
    cred = msg["credential"]
    return Hello(
        app_name=_ascii(msg["app_name"], "app_name", 64),
        host_name=_ascii(msg["host_name"], "host_name", 64),
        transport=_choice(msg["transport"], "transport", ("usb", "ble", "auto")),
        credential=None if cred is None else _base64(cred, "credential", MAX_CREDENTIAL),
    )


def parse_identity(value: Any) -> dict[str, Any]:
    names = {"proto", "user", "host", "port", "path", "index"}
    if type(value) is not dict or set(value) != names:
        raise bad_request("identity: unknown or missing fields")
    user, port, path = value["user"], value["port"], value["path"]
    if port is not None and (
        type(port) is not str or not 1 <= len(port) <= 5 or set(port) - DIGITS
    ):
        raise bad_request("identity.port: 1-5 ASCII digits required")
    if path is not None and not _ascii(path, "identity.path", 128, "@").startswith("/"):
        raise bad_request("identity.path: must start with /")
    return {
        "proto": _choice(value["proto"], "identity.proto", ("ssh", "gpg")),
        "user": None if user is None else _token(user, "identity.user"),
        "host": _token(value["host"], "identity.host"),
        "port": port,
        "path": path,
        "index": _uint(value["index"], "identity.index", 0, U32_MAX),
    }


def parse_sign(msg: dict[str, Any]) -> SignRequest:
    if msg.get("type") != "sign_identity":
        raise bad_request("expected sign_identity")
    _fields(msg, "id", "identity", "curve", "challenge_hidden", "challenge_visual", "passphrase")
    identity = parse_identity(msg["identity"])
    curve = _choice(msg["curve"], "curve", ("ed25519", "nist256p1"))
    hidden = _base64(msg["challenge_hidden"], "challenge_hidden", MAX_CHALLENGE)
    if identity["proto"] == "gpg" and curve == "nist256p1" and len(hidden) != 32:
        raise bad_request("challenge_hidden: gpg/nist256p1 requires a 32-byte digest")
    visual = msg["challenge_visual"]
    if type(visual) is not str or len(visual) > MAX_VISUAL or not visual.isprintable():
        raise bad_request(f"challenge_visual: 0-{MAX_VISUAL} printable characters required")
    return SignRequest(
        id=_uint(msg["id"], "id", 1, U32_MAX),
        identity=identity,
        curve=curve,
        challenge_hidden=hidden,
        challenge_visual=visual,
        passphrase=_choice(msg["passphrase"], "passphrase", ("standard", "ask")),
    )


def parse_pairing_code(msg: dict[str, Any]) -> str:
    if msg.get("type") != "pairing_code":
        raise bad_request("expected pairing_code")
    _fields(msg, "code")
    code = msg["code"]
    if type(code) is not str or len(code) != 6 or set(code) - DIGITS:
        raise bad_request("code: exactly 6 ASCII digits required")
    return code


def ready_frame(ready: Ready) -> dict[str, Any]:
    """The `ready` frame; fails instead of sending values the host would reject."""
    for name in ("model", "internal_model", "firmware"):
        if not _is_ascii(getattr(ready, name), 64, first=" "):
            raise HelperError("device_error", f"device reported an invalid {name}")
    cred = ready.credential
    if cred is not None and not 1 <= len(cred) <= MAX_CREDENTIAL:
        raise HelperError("internal", "credential blob too large")
    device = asdict(ready)
    del device["credential"]
    return {"type": "ready", "device": device, "credential": None if cred is None else b64(cred)}


# ---- credential blob (opaque to the host) ------------------------------------------------


@dataclass(frozen=True, repr=False)  # repr=False: never print secrets
class PairingCredential:
    """THP pairing credential; duck-types `trezorlib.thp.credentials.Credential`.

    Blob: trezor_pubkey (32 bytes) || host_privkey (32 bytes) || credential (1-1024 bytes).
    """

    trezor_pubkey: bytes
    host_privkey: bytes
    credential: bytes

    def encode(self) -> bytes:
        blob = self.trezor_pubkey + self.host_privkey + self.credential
        if PairingCredential.decode(blob) != self:  # a field has the wrong size
            raise HelperError("pairing_failed", "device issued a malformed credential")
        return blob

    @staticmethod
    def decode(blob: bytes) -> PairingCredential | None:
        """None for anything malformed: the caller falls back to code-entry pairing."""
        if not 64 < len(blob) <= 64 + 1024:
            return None
        return PairingCredential(blob[:32], blob[32:64], blob[64:])


# ---- protocol state machine --------------------------------------------------------------


class Server:
    """hello -> ready, then sign_identity requests until EOF.

    `device` has `open(hello, ui) -> Ready` and `sign(request) -> (public_key, signature)`;
    the server itself is the `ui` (`button()`, `pairing_code()`).
    """

    def __init__(self, rx: BinaryIO, tx: BinaryIO, device: Any) -> None:
        self._rx, self._tx, self._device = rx, tx, device

    def _send(self, obj: dict[str, Any]) -> None:
        self._tx.write(encode_frame(obj))
        self._tx.flush()

    def _send_error(self, err: HelperError, req_id: int | None) -> None:
        print(f"petschaft-helper: {err.code}: {err.message}", file=sys.stderr)
        msg = {"type": "error", "id": req_id, "code": err.code, "message": err.message}
        with suppress(OSError):  # host is gone: nothing left to tell it
            self._send({**msg, "fatal": err.fatal})

    def button(self) -> None:
        self._send({"type": "event", "event": "button"})

    def pairing_code(self) -> str:
        self._send({"type": "event", "event": "pairing_code_required"})
        return parse_pairing_code(read_frame(self._rx))

    def run(self) -> int:
        req_id: int | None = None
        try:
            try:
                ready = ready_frame(self._device.open(parse_hello(read_frame(self._rx)), self))
            except HelperError as err:
                err.fatal = True  # hello is sent exactly once: no way to continue
                raise
            self._send(ready)
            while True:
                req_id = None
                msg = read_frame(self._rx)
                raw_id = msg.get("id")
                req_id = raw_id if type(raw_id) is int and 1 <= raw_id <= U32_MAX else None
                req = parse_sign(msg)
                try:
                    public_key, signature = self._device.sign(req)
                except HelperError as err:
                    if err.fatal:
                        raise
                    self._send_error(err, req.id)
                    continue
                signed = {"public_key": b64(public_key), "signature": b64(signature)}
                self._send({"type": "signed", "id": req.id, **signed})
        except EndOfInput:
            return 0
        except HelperError as err:
            self._send_error(err, req_id)
        except Exception as exc:  # noqa: BLE001 - last resort: report, never crash silently
            self._send_error(HelperError("internal", f"unexpected {type(exc).__name__}"), req_id)
        return 1


# ---- trezorlib-backed device (covered by the on-device test only) -------------------------


def trezor_error(exc: Exception) -> HelperError:
    """Map a trezorlib (or OS) exception to a protocol error without leaking its text."""
    from trezorlib import exceptions as ex
    from trezorlib.messages import FailureType

    name = type(exc).__name__
    failure = exc.code if isinstance(exc, ex.TrezorFailure) else None
    if isinstance(exc, ex.Cancelled) or failure in (
        FailureType.ActionCancelled,
        FailureType.PinCancelled,
    ):
        return HelperError("cancelled", "cancelled on the device")
    if isinstance(exc, ex.PassphraseError):
        return HelperError("passphrase_unavailable", "passphrase is not available")
    if isinstance(exc, ex.TrezorFailure):
        code = failure.name if isinstance(failure, FailureType) else "unknown"
        return HelperError("device_error", f"device reported failure: {code}")
    if isinstance(exc, ex.OutdatedFirmwareError | ex.MissingCapability | ex.InvalidSessionError):
        return HelperError("device_error", f"device error ({name})")
    if isinstance(exc, ConnectionRefusedError) and exc.args == (BLE_NOT_PAIRED,):
        msg = "Bluetooth: the Trezor is not paired with this computer; pair it once with the "
        msg += "system (e.g. bluetoothctl), see docs/nix.md"
        return HelperError("device_error", msg, fatal=True)
    if isinstance(exc, TimeoutError) and exc.args == (BLE_CONNECT_TIMED_OUT,):
        msg = "Bluetooth: connecting to the Trezor timed out (is it awake, in range and not "
        msg += "connected to another computer?)"
        return HelperError("device_error", msg, fatal=True)
    if isinstance(exc, ex.TrezorException | OSError):  # transport, THP, locked, busy, ...
        return HelperError("device_error", f"device communication failed ({name})", fatal=True)
    return HelperError("internal", f"unexpected {name}")


@contextmanager
def _mapped() -> Iterator[None]:
    try:
        yield
    except HelperError:
        raise
    except Exception as exc:  # noqa: BLE001 - every library error becomes a protocol error
        raise trezor_error(exc) from None


def _raise_scan_timeout(_signum: int, _frame: object) -> None:
    # A HelperError, so that even an alarm racing the `finally` below fails closed.
    raise HelperError("device_not_found", "Bluetooth scan timed out")


def _enumerate(kind: str) -> list[Any]:
    """Devices of one transport, [] on any failure. Never calls get_transport(None), which
    would also try the bridge/UDP transports (network) and can block indefinitely."""
    from trezorlib.transport.ble import BleTransport
    from trezorlib.transport.webusb import WebUsbTransport

    if kind == "usb":
        try:
            return list(WebUsbTransport.enumerate()) if WebUsbTransport.ENABLED else []
        except Exception:  # noqa: BLE001 - e.g. no libusb: treated as "no device"
            return []
    if not BleTransport.ENABLED:
        return []
    # The macOS Bluetooth permission prompt can block the scan forever: bound it.
    previous = signal.signal(signal.SIGALRM, _raise_scan_timeout)
    signal.setitimer(signal.ITIMER_REAL, BLE_SCAN_TIMEOUT)
    try:
        return list(ble_transport().enumerate())
    except Exception:  # noqa: BLE001 - Bluetooth off/unauthorized/timeout: "no device"
        return []
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


# ---- Bluetooth on Linux --------------------------------------------------------------------
#
# trezorlib scans for 3 s, stops the scan and then connects with a 3 s timeout. BlueZ does
# not complete a connection to an LE device it does not see: with the scan stopped it waits
# in a filtered passive scan that never reports the (bonded) Trezor, and the connection
# times out. Trezor Suite keeps the scan running during a connection on Linux for this
# reason (trezor-suite packages/transport-bluetooth/src/server/scan_coordinator.rs). On
# Linux the helper does the same in its own subclass of trezorlib's BLE process; macOS
# (CoreBluetooth) keeps trezorlib's behaviour unchanged.


def ble_transport() -> Any:
    """trezorlib's BleTransport, or on Linux a subclass whose BLE process connects as above."""
    from trezorlib.transport.ble import BleProxy, BleTransport

    if not sys.platform.startswith("linux"):
        return BleTransport

    class LinuxBleProxy(BleProxy):
        def __init__(self) -> None:  # replaces trezorlib's, which would start its own child
            parent_pipe, child_pipe = multiprocessing.Pipe()
            self.pipe = parent_pipe
            self.process = multiprocessing.Process(
                target=run_linux_ble, args=(child_pipe,), daemon=True
            )
            self.process.start()
            atexit.register(self._shutdown)

    class LinuxBleTransport(BleTransport):
        @classmethod
        def ble_proxy(cls) -> Any:
            # Stored on BleTransport: the transports that enumerate() returns are plain
            # BleTransport objects, and stop_ble() looks there too.
            if BleTransport._ble is None:
                BleTransport._ble = LinuxBleProxy()
            return BleTransport._ble

    return LinuxBleTransport


def run_linux_ble(pipe: Any) -> None:
    """Entry point of the BLE child process on Linux (started with "spawn", see main; it
    inherits the core dump limit, but not the logging setup)."""
    logging.disable(logging.CRITICAL)  # as in the parent: trezorlib logs must never carry secrets
    linux_ble_async()(pipe)


def linux_ble_async() -> Any:
    """trezorlib's BleAsync with a connect() that keeps scanning until it is connected."""
    import asyncio

    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakDBusError, BleakError
    from trezorlib.transport import ble

    class LinuxBleAsync(ble.BleAsync):
        async def connect(self, address: str) -> None:
            if not self.did_scan:
                await self.scan()
            periph = self.devices.get(address)
            if periph is None:
                raise RuntimeError("BLE device not found")
            if periph.client is not None:
                return
            client = BleakClient(
                periph.device, services=[ble.TREZOR_SERVICE_UUID], timeout=BLE_CONNECT_TIMEOUT
            )
            # Started before Connect: starting a discovery during a connection can abort it.
            scanner = BleakScanner()
            await scanner.start()
            try:
                await client.connect()
            except TimeoutError:
                raise TimeoutError(BLE_CONNECT_TIMED_OUT) from None
            finally:
                with suppress(BleakError, OSError):
                    await scanner.stop()
            try:
                # Pairing needs a BlueZ agent (the Trezor expects DisplayYesNo); the helper has
                # none, so the bond must exist already (bleak skips Pair for a paired device).
                try:
                    await client.pair()
                except BleakDBusError as err:
                    if err.dbus_error in BLUEZ_AUTH_ERRORS:
                        raise ConnectionRefusedError(BLE_NOT_PAIRED) from None
                    raise
                queue: asyncio.Queue[bytearray] = asyncio.Queue()

                async def read_callback(_characteristic: Any, data: bytearray) -> None:
                    await queue.put(data)

                await client.start_notify(ble.TREZOR_CHARACTERISTIC_TX, read_callback)
            except BaseException:
                with suppress(Exception):  # best effort: the original error is what counts
                    await client.disconnect()
                raise
            periph.client = client
            periph.queue = queue  # set only after the notifications run, as trezorlib does

    return LinuxBleAsync


def find_transport(kind: str) -> Any:
    """usb: WebUSB only; ble: Bluetooth only; auto: USB if a device is present, else BLE.
    More than one device on the chosen transport is an error, never a guess."""
    for candidate in ("usb", "ble"):
        if kind in (candidate, "auto") and (found := _enumerate(candidate)):
            if len(found) > 1:
                msg = "more than one Trezor found; connect only one"
                raise HelperError("device_error", msg, fatal=True)
            return found[0]
    where = {"usb": "USB", "ble": "Bluetooth", "auto": "USB or Bluetooth"}[kind]
    raise HelperError("device_not_found", f"no Trezor found via {where}")


def _pair(client: Any, ui: Server) -> PairingCredential | None:
    """Code-entry pairing; returns a new normal (never autoconnect) credential."""
    from trezorlib import exceptions as ex
    from trezorlib.thp.pairing import CodeEntry

    pairing = client.pairing
    client.connect()  # opens the channel (unlocking the device) if not yet open
    if pairing.is_paired():
        return None
    if CodeEntry not in pairing.methods:
        raise HelperError("pairing_failed", "device does not offer code-entry pairing")
    try:
        method = CodeEntry(pairing)
        method.send_code(ui.pairing_code())
        cred = pairing.request_credential(autoconnect=False)
        pairing.finish()
    except ex.Cancelled:
        raise HelperError("cancelled", "pairing cancelled on the device") from None
    except (ex.TrezorFailure, ex.ProtocolError, ex.StateMismatchError, ValueError):
        raise HelperError("pairing_failed", "pairing failed (wrong code?)") from None
    return PairingCredential(cred.trezor_pubkey, cred.host_privkey, cred.credential)


class TrezorDevice:
    def __init__(self) -> None:
        self._client: Any = None
        self._standard: Any = None  # reused standard-wallet session

    def open(self, hello: Hello, ui: Server) -> Ready:
        from trezorlib.client import AppManifest, get_client
        from trezorlib.thp.client import TrezorClientThp

        with _mapped():
            transport = find_transport(hello.transport)
            known = None if hello.credential is None else PairingCredential.decode(hello.credential)
            app = AppManifest(
                app_name=hello.app_name,
                host_name=hello.host_name,
                button_callback=lambda _msg: ui.button(),
                credentials=() if known is None else (known,),
            )
            client = get_client(app, transport)
            if not isinstance(client, TrezorClientThp):  # protocol v1: no pairing, no THP
                raise HelperError("device_error", "device does not support THP", fatal=True)
            self._client = client
            new = None if client.pairing.is_paired() else _pair(client, ui)
            client.ensure_unlocked()
            f = client.features
            if not f.initialized:
                raise HelperError("device_not_initialized", "device has no seed; set it up first")
            return Ready(
                model=client.model.name,
                internal_model=f.internal_model or client.model.internal_name,
                firmware=f"{f.major_version}.{f.minor_version}.{f.patch_version}",
                passphrase_protection=f.passphrase_protection is True,
                credential=None if new is None else new.encode(),
            )

    def sign(self, request: SignRequest) -> tuple[bytes, bytes]:
        from trezorlib import messages, misc
        from trezorlib.client import PassphraseSetting
        from trezorlib.exceptions import MissingCapability

        client = self._client
        if client is None:
            raise HelperError("internal", "device not open")
        identity = messages.IdentityType(**request.identity)

        def sign_with(session: Any) -> tuple[bytes, bytes]:
            r = misc.sign_identity(
                session, identity, request.challenge_hidden, request.challenge_visual, request.curve
            )
            return r.public_key, r.signature

        with _mapped():
            if request.passphrase == "ask":  # noqa: S105 - policy name, not a secret
                # trezorlib raises PassphraseError only for `passphrase_protection is False`;
                # an unreported value (None) must not leave the decision to the firmware.
                if client.features.passphrase_protection is not True:
                    raise HelperError("passphrase_unavailable", "passphrase protection is disabled")
                try:
                    session = client.get_session(PassphraseSetting.ON_DEVICE)
                except MissingCapability:
                    raise HelperError("passphrase_unavailable", "no on-device passphrase") from None
                try:
                    return sign_with(session)
                finally:
                    session.close()
            if self._standard is None:
                self._standard = client.get_session(PassphraseSetting.STANDARD_WALLET)
            try:
                return sign_with(self._standard)
            except BaseException:
                self._standard = None  # next request derives a fresh session
                raise


# ---- entry point -------------------------------------------------------------------------


def stop_ble() -> None:
    """Kill trezorlib's BLE proxy process, if one was started, so that it cannot outlive a
    failed helper (its atexit handler would wait up to 10 s for a stuck child)."""
    ble = sys.modules.get("trezorlib.transport.ble")
    proxy = getattr(getattr(ble, "BleTransport", None), "_ble", None)
    if proxy is not None and proxy.process is not None:
        proxy.process.kill()
        proxy.process.join(2)
        proxy.process = proxy.pipe = None  # makes trezorlib's atexit shutdown a no-op


def main(device: Any = None) -> int:
    """`device` is for tests only; the production entry point never passes one."""
    with suppress(ValueError, OSError):  # no core dumps of keys or credentials
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # trezorlib's BLE proxy is a multiprocessing.Process. "fork" (the Linux default)
    # would hand it every fd of this process, including the frame pipe, so it could keep
    # the host waiting after the helper died; "spawn" starts a fresh interpreter.
    multiprocessing.set_start_method("spawn", force=True)
    # Frames go to a private (non-inheritable) duplicate of stdout; fd 1 and sys.stdout
    # then point at stderr, so nothing printed by libraries or children reaches the host.
    sys.stdout.flush()
    frame_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    with open(frame_fd, "wb") as tx:
        if device is None:
            logging.disable(logging.CRITICAL)  # trezorlib logs must never carry secrets
            device = TrezorDevice()
        rc = Server(sys.stdin.buffer, tx, device).run()
    if rc:
        stop_ble()
    return rc


if __name__ == "__main__":
    sys.exit(main())
