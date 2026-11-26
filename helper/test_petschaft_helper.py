"""Tests for petschaft_helper without a device (docs/helper-protocol.md, version 1)."""

from __future__ import annotations

import base64
import io
import json
import multiprocessing
import random
import re
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import petschaft_helper as th
from fake_helper import CREDENTIAL, PAIRING_CODE, FakeDevice, fake_signature

HERE = Path(__file__).resolve().parent
U32 = 2**32

# ---- helpers ---------------------------------------------------------------------------


def raw(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


def frame(obj: Any) -> bytes:
    return raw(json.dumps(obj).encode())


def parse_frames(data: bytes) -> list[dict[str, Any]]:
    """Strict: the stream must consist of complete frames only."""
    out = []
    while data:
        assert len(data) >= 4, f"trailing garbage: {data!r}"
        (n,) = struct.unpack(">I", data[:4])
        assert 1 <= n <= th.MAX_FRAME and len(data) >= 4 + n
        obj = json.loads(data[4 : 4 + n].decode("utf-8"))
        assert isinstance(obj, dict)
        out.append(obj)
        data = data[4 + n :]
    return out


def hello(**kw: Any) -> dict[str, Any]:
    msg = {
        "type": "hello",
        "version": 1,
        "app_name": "petschaft",
        "host_name": "mac",
        "transport": "auto",
        "credential": base64.b64encode(CREDENTIAL.encode()).decode(),
    }
    msg.update(kw)
    return msg


def identity(**kw: Any) -> dict[str, Any]:
    ident = {"proto": "ssh", "user": "user", "host": "homelab", "port": None, "path": None}
    ident["index"] = 0
    ident.update(kw)
    return ident


def sign(**kw: Any) -> dict[str, Any]:
    msg = {
        "type": "sign_identity",
        "id": 1,
        "identity": identity(),
        "curve": "ed25519",
        "challenge_hidden": base64.b64encode(b"\x11" * 32).decode(),
        "challenge_visual": "pets: Login homelab",
        "passphrase": "standard",
    }
    msg.update(kw)
    return msg


def run(data: bytes, device: FakeDevice | None = None) -> tuple[int, list[dict[str, Any]]]:
    tx = io.BytesIO()
    rc = th.Server(io.BytesIO(data), tx, device or FakeDevice()).run()
    return rc, parse_frames(tx.getvalue())


def assert_fatal(rc: int, out: list[dict[str, Any]], code: str = "bad_request") -> dict:
    assert rc == 1
    err = out[-1]
    assert err["type"] == "error" and err["code"] == code and err["fatal"] is True
    assert set(err) == {"type", "id", "code", "message", "fatal"}
    assert len(err["message"]) <= th.MAX_MESSAGE
    return err


def sign_result(msg: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    return run(frame(hello()) + frame(msg))


def assert_sign_rejected(msg: dict[str, Any]) -> None:
    rc, out = sign_result(msg)
    assert out[0]["type"] == "ready"
    assert_fatal(rc, out)


def assert_sign_ok(msg: dict[str, Any]) -> None:
    rc, out = sign_result(msg)
    assert rc == 0 and out[-1]["type"] == "signed", out


# ---- framing ---------------------------------------------------------------------------


def test_eof_before_any_frame_exits_0_silently() -> None:
    assert run(b"") == (0, [])


def test_eof_after_ready_exits_0() -> None:
    rc, out = run(frame(hello()))
    assert rc == 0 and [m["type"] for m in out] == ["ready"]


@pytest.mark.parametrize("length", [0, th.MAX_FRAME + 1, 2**32 - 1])
def test_bad_frame_length(length: int) -> None:
    rc, out = run(struct.pack(">I", length) + b"{}")
    assert assert_fatal(rc, out)["id"] is None


def test_max_frame_length_accepted_and_min_length_reaches_json() -> None:
    body = json.dumps(hello()).encode()
    body += b" " * (th.MAX_FRAME - len(body))
    rc, out = run(raw(body))
    assert rc == 0 and out[0]["type"] == "ready"
    rc, out = run(raw(b"1"))
    assert assert_fatal(rc, out)["message"] == "frame is not a JSON object"


@pytest.mark.parametrize("data", [b"\x00\x00", struct.pack(">I", 10) + b"{}"])
def test_truncated_frame(data: bytes) -> None:
    assert_fatal(*run(data))


@pytest.mark.parametrize(
    "body",
    [
        b'{"type":"hello\xff"}',  # invalid UTF-8
        b'{"type":"\xc0\xaf"}',  # overlong encoding
        b'{"type":"\xed\xa0\x80"}',  # UTF-8-encoded surrogate
        b"\xef\xbb\xbf{}",  # BOM
        b"{",
        b"{}x",
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"type":"hello","type":"hello"}',  # duplicate key
        b"[" * 60000 + b"]" * 5000,  # deep nesting
        b'{"a":1' + b"0" * 5000 + b"}",  # integer too long for Python's int()
    ],
)
def test_invalid_json(body: bytes) -> None:
    rc, out = run(raw(body))
    assert_fatal(rc, out)


def test_duplicate_key_rejected_even_if_last_value_is_valid() -> None:
    body = json.dumps(hello()).encode()
    body = body.replace(b'"version": 1', b'"version": 2, "version": 1')
    assert body.count(b'"version"') == 2
    assert_fatal(*run(raw(body)))


@pytest.mark.parametrize("body", [b"[]", b'"hello"', b"null", b"1", b"true"])
def test_non_object(body: bytes) -> None:
    assert_fatal(*run(raw(body)))


def random_json(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randrange(7 if depth < 3 else 4)
    if kind == 0:
        return rng.randrange(-(2**40), 2**40)
    if kind == 1:
        return "".join(
            chr(rng.choice([rng.randrange(32, 127), rng.randrange(0x80, 0xD7FF)]))
            for _ in range(rng.randrange(8))
        )
    if kind == 2:
        return rng.choice([None, True, False])
    if kind == 3:
        return rng.random()
    if kind in (4, 5):
        return {f"k{i}": random_json(rng, depth + 1) for i in range(rng.randrange(4))}
    return [random_json(rng, depth + 1) for _ in range(rng.randrange(4))]


def test_property_frame_roundtrip() -> None:
    rng = random.Random(1)
    for _ in range(500):
        obj = {f"f{i}": random_json(rng) for i in range(rng.randrange(1, 5))}
        encoded = th.encode_frame(obj)
        rx = io.BytesIO(encoded)
        assert th.read_frame(rx) == obj and rx.read() == b""


def test_encode_frame_rejects_oversize() -> None:
    with pytest.raises(th.HelperError):
        th.encode_frame({"x": "a" * th.MAX_FRAME})


# ---- hello -----------------------------------------------------------------------------


def test_hello_with_valid_credential_ready_without_new_credential() -> None:
    dev = FakeDevice()
    rc, out = run(frame(hello()), dev)
    assert rc == 0
    assert out == [
        {
            "type": "ready",
            "device": {
                "model": "Safe 7",
                "internal_model": "T3W1",
                "firmware": "2.13.1",
                "passphrase_protection": True,
            },
            "credential": None,
        }
    ]
    assert dev.hellos[0].credential == CREDENTIAL.encode()


@pytest.mark.parametrize("transport", ["usb", "ble", "auto"])
def test_hello_transport_values(transport: str) -> None:
    dev = FakeDevice()
    run(frame(hello(transport=transport)), dev)
    assert dev.hellos[0].transport == transport


@pytest.mark.parametrize(
    "change",
    [
        {"version": 2},
        {"version": "1"},
        {"version": True},
        {"version": 1.0},
        {"app_name": ""},
        {"app_name": "a" * 65},
        {"app_name": "tr zr"},
        {"app_name": "petschaft\n"},
        {"app_name": "petschaftä"},
        {"app_name": None},
        {"host_name": ""},
        {"host_name": "h" * 65},
        {"host_name": "my mac"},
        {"host_name": "\x7f"},
        {"transport": "USB"},
        {"transport": "bluetooth"},
        {"transport": None},
        {"credential": "QR=="},  # non-canonical trailing bits
        {"credential": "QQ"},  # missing padding
        {"credential": "QQ==\n"},
        {"credential": "Q Q=="},
        {"credential": "-_8="},  # URL-safe alphabet
        {"credential": "äää="},
        {"credential": 5},
        {"credential": base64.b64encode(b"x" * 4097).decode()},
        {"extra": 1},
        {"type": "pairing_code"},
        {"type": "sign_identity"},
        {"type": "nonsense"},
        {"type": None},
    ],
)
def test_hello_rejected(change: dict[str, Any]) -> None:
    dev = FakeDevice()
    rc, out = run(frame(hello(**change)), dev)
    assert assert_fatal(rc, out)["id"] is None
    assert dev.hellos == []


@pytest.mark.parametrize("field", ["version", "app_name", "host_name", "transport", "credential"])
def test_hello_missing_field(field: str) -> None:
    msg = hello()
    del msg[field]
    assert_fatal(*run(frame(msg)))


def test_hello_boundaries_accepted() -> None:
    for change in [
        {"app_name": "a" * 64, "host_name": "!~" * 32},
        {"app_name": "x", "host_name": "y"},
        {"credential": base64.b64encode(b"x" * 4096).decode()},  # unusable: pairs again
        {"credential": ""},
    ]:
        msg = hello(**{"credential": None, **change})
        rc, out = run(frame(msg) + frame({"type": "pairing_code", "code": PAIRING_CODE}))
        assert rc == 0 and out[-1]["type"] == "ready", (change, out)


def test_second_hello_rejected() -> None:
    rc, out = run(frame(hello()) + frame(hello()))
    assert out[0]["type"] == "ready"
    assert_fatal(rc, out)


def test_device_errors_on_hello_are_fatal() -> None:
    rc, out = run(frame(hello()), FakeDevice(initialized=False))
    assert_fatal(rc, out, "device_not_initialized")

    class Failing(FakeDevice):
        def open(self, hello: th.Hello, ui: th.Ui) -> th.Ready:
            raise th.HelperError("cancelled", "pairing cancelled")

    rc, out = run(frame(hello()), Failing())
    assert out[-1]["code"] == "cancelled" and out[-1]["fatal"] is True and rc == 1


# ---- pairing ---------------------------------------------------------------------------


def code(value: Any) -> bytes:
    return frame({"type": "pairing_code", "code": value})


@pytest.mark.parametrize(
    "cred",
    [None, base64.b64encode(b"garbage").decode(), base64.b64encode(b'{"a":1}').decode()],
)
def test_pairing_flow_returns_new_credential(cred: str | None) -> None:
    rc, out = run(frame(hello(credential=cred)) + code(PAIRING_CODE) + frame(sign()))
    assert rc == 0
    assert [m.get("event", m["type"]) for m in out] == [
        "button",
        "pairing_code_required",
        "ready",
        "button",
        "signed",
    ]
    assert base64.b64decode(out[2]["credential"]) == CREDENTIAL.encode()


@pytest.mark.parametrize(
    "bad",
    [
        code("62056"),
        code("6205677"),
        code("62056a"),
        code(
            "\uff16\uff12\uff10\uff15\uff16\uff17"
        ),  # fullwidth digits: str.isdigit() would accept them
        code("62056\n"),
        code(620567),
        code(None),
        frame({"type": "pairing_code", "code": PAIRING_CODE, "extra": 1}),
        frame({"type": "pairing_code"}),
        frame(sign()),
        frame(hello()),
        raw(b"not json"),
    ],
)
def test_pairing_code_rejected(bad: bytes) -> None:
    rc, out = run(frame(hello(credential=None)) + bad)
    assert [m.get("event") for m in out[:2]] == ["button", "pairing_code_required"]
    assert_fatal(rc, out)


def test_wrong_pairing_code_is_pairing_failed() -> None:
    rc, out = run(frame(hello(credential=None)) + code("000000"))
    assert_fatal(rc, out, "pairing_failed")


def test_eof_while_waiting_for_pairing_code_exits_0() -> None:
    rc, out = run(frame(hello(credential=None)))
    assert rc == 0 and out[-1] == {"type": "event", "event": "pairing_code_required"}


def test_pairing_code_outside_pairing_rejected() -> None:
    rc, out = run(frame(hello()) + code(PAIRING_CODE))
    assert out[0]["type"] == "ready"
    assert_fatal(rc, out)


# ---- sign_identity ---------------------------------------------------------------------


def test_sign_returns_raw_device_values() -> None:
    dev = FakeDevice()
    rc, out = run(frame(hello()) + frame(sign(id=7)), dev)
    pub, sig = fake_signature(dev.requests[0])
    assert rc == 0
    assert out[-2:] == [
        {"type": "event", "event": "button"},
        {
            "type": "signed",
            "id": 7,
            "public_key": base64.b64encode(pub).decode(),
            "signature": base64.b64encode(sig).decode(),
        },
    ]
    req = dev.requests[0]
    assert req.identity == identity()
    assert req.challenge_hidden == b"\x11" * 32 and req.curve == "ed25519"


def test_sequential_requests() -> None:
    data = frame(hello()) + b"".join(frame(sign(id=i)) for i in (1, 2, 3))
    rc, out = run(data)
    assert rc == 0 and [m["id"] for m in out if m["type"] == "signed"] == [1, 2, 3]


@pytest.mark.parametrize("good", [1, U32 - 1])
def test_id_boundaries_ok(good: int) -> None:
    assert_sign_ok(sign(id=good))


@pytest.mark.parametrize("bad", [0, -1, U32, True, 1.0, "1", None])
def test_id_rejected(bad: Any) -> None:
    rc, out = sign_result(sign(id=bad))
    assert assert_fatal(rc, out)["id"] is None


def test_bad_request_echoes_valid_id() -> None:
    rc, out = sign_result(sign(id=9, curve="secp256k1"))
    assert assert_fatal(rc, out)["id"] == 9


TOKEN_BAD = ["", "a" * 129, "a/b", "a@b", "a:b", "a b", "a\x7f", "é", "a\x00", 5, ["a"]]
TOKEN_OK = ["a", "a" * 128, "!#$%&'()*+,-.;<=>?[\\]^_`{|}~09AZaz", '"quoted"']


@pytest.mark.parametrize("value", TOKEN_OK)
@pytest.mark.parametrize("name", ["user", "host"])
def test_token_ok(name: str, value: str) -> None:
    assert_sign_ok(sign(identity=identity(**{name: value})))


@pytest.mark.parametrize("value", TOKEN_BAD)
@pytest.mark.parametrize("name", ["user", "host"])
def test_token_rejected(name: str, value: Any) -> None:
    assert_sign_rejected(sign(identity=identity(**{name: value})))


@pytest.mark.parametrize(
    "change",
    [
        {"user": None},
        {"port": "0"},
        {"port": "22"},
        {"port": "99999"},
        {"path": "/"},
        {"path": "/" + "a" * 127},
        {"path": "/a/b:c?d=e#f"},
        {"index": 0},
        {"index": U32 - 1},
        {"proto": "gpg"},
    ],
)
def test_identity_ok(change: dict[str, Any]) -> None:
    assert_sign_ok(sign(identity=identity(**change)))


@pytest.mark.parametrize(
    "change",
    [
        {"proto": "SSH"},
        {"proto": "https"},
        {"proto": None},
        {"host": None},
        {"port": ""},
        {"port": "123456"},
        {"port": "22a"},
        {"port": "\uff12\uff12"},
        {"port": 22},
        {"path": ""},
        {"path": "a/b"},
        {"path": "/a@b"},
        {"path": "/a b"},
        {"path": "/ä"},
        {"path": "/" + "a" * 128},
        {"path": 5},
        {"index": -1},
        {"index": U32},
        {"index": True},
        {"index": 0.0},
        {"index": None},
        {"extra": 1},
    ],
)
def test_identity_rejected(change: dict[str, Any]) -> None:
    assert_sign_rejected(sign(identity=identity(**change)))


@pytest.mark.parametrize("field", ["proto", "user", "host", "port", "path", "index"])
def test_identity_missing_field(field: str) -> None:
    ident = identity()
    del ident[field]
    assert_sign_rejected(sign(identity=ident))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.mark.parametrize(
    ("proto", "curve", "size"),
    [
        ("ssh", "ed25519", 0),
        ("ssh", "ed25519", 512),
        ("ssh", "nist256p1", 0),
        ("ssh", "nist256p1", 512),
        ("gpg", "ed25519", 0),
        ("gpg", "ed25519", 512),
        ("gpg", "nist256p1", 32),
    ],
)
def test_challenge_ok(proto: str, curve: str, size: int) -> None:
    ident = identity(proto=proto)
    assert_sign_ok(sign(identity=ident, curve=curve, challenge_hidden=b64(b"\x00" * size)))


@pytest.mark.parametrize(
    ("proto", "curve", "size"),
    [
        ("ssh", "ed25519", 513),
        ("ssh", "nist256p1", 513),
        ("gpg", "ed25519", 513),
        ("gpg", "nist256p1", 0),
        ("gpg", "nist256p1", 31),
        ("gpg", "nist256p1", 33),
        ("gpg", "nist256p1", 64),
    ],
)
def test_challenge_rejected(proto: str, curve: str, size: int) -> None:
    ident = identity(proto=proto)
    assert_sign_rejected(sign(identity=ident, curve=curve, challenge_hidden=b64(b"\x00" * size)))


@pytest.mark.parametrize("bad", ["AA=", "AA", "AB==", "AA==AA==", None, 0])
def test_challenge_bad_base64(bad: Any) -> None:
    assert_sign_rejected(sign(challenge_hidden=bad))


@pytest.mark.parametrize("value", ["", "a" * 128, "ä" * 128, "Login 🙂 homelab", "a b"])
def test_challenge_visual_ok(value: str) -> None:
    assert_sign_ok(sign(challenge_visual=value))


@pytest.mark.parametrize(
    "value", ["a" * 129, "a\nb", "\x00", "\x1b[2J", "\u202e", "\u200b", "\ud800", "\x85", None, 1]
)
def test_challenge_visual_rejected(value: Any) -> None:
    assert_sign_rejected(sign(challenge_visual=value))


@pytest.mark.parametrize(
    "change",
    [{"curve": "Ed25519"}, {"curve": None}, {"passphrase": "none"}, {"passphrase": ""}, {"x": 1}],
)
def test_sign_enum_and_unknown_fields(change: dict[str, Any]) -> None:
    assert_sign_rejected(sign(**change))


@pytest.mark.parametrize(
    "field", ["id", "identity", "curve", "challenge_hidden", "challenge_visual", "passphrase"]
)
def test_sign_missing_field(field: str) -> None:
    msg = sign()
    del msg[field]
    assert_sign_rejected(msg)


def test_sign_identity_not_object() -> None:
    assert_sign_rejected(sign(identity=["ssh", "user", "homelab"]))


def test_non_fatal_error_then_next_request_served() -> None:
    dev = FakeDevice(sign_errors=[th.HelperError("cancelled", "rejected on device")])
    rc, out = run(frame(hello()) + frame(sign(id=4)) + frame(sign(id=5)), dev)
    assert rc == 0
    errors = [m for m in out if m["type"] == "error"]
    assert errors == [
        {
            "type": "error",
            "id": 4,
            "code": "cancelled",
            "message": "rejected on device",
            "fatal": False,
        }
    ]
    assert out[-1]["type"] == "signed" and out[-1]["id"] == 5


def test_passphrase_unavailable_is_non_fatal() -> None:
    dev = FakeDevice(passphrase_protection=False)
    rc, out = run(frame(hello()) + frame(sign(passphrase="ask")) + frame(sign(id=2)), dev)
    assert rc == 0
    assert out[1]["code"] == "passphrase_unavailable" and out[1]["fatal"] is False
    assert out[-1]["type"] == "signed"


def test_unexpected_exception_is_internal_and_does_not_leak() -> None:
    dev = FakeDevice(sign_errors=[RuntimeError("secret-xyz")])
    rc, out = run(frame(hello()) + frame(sign(id=3)) + frame(sign(id=4)), dev)
    err = assert_fatal(rc, out, "internal")
    assert err["id"] == 3 and "secret-xyz" not in err["message"]
    assert len(dev.requests) == 1


def test_fatal_device_error_stops() -> None:
    dev = FakeDevice(sign_errors=[th.HelperError("device_error", "gone", fatal=True)])
    rc, out = run(frame(hello()) + frame(sign(id=3)) + frame(sign(id=4)), dev)
    assert assert_fatal(rc, out, "device_error")["id"] == 3


def test_protocol_error_after_non_fatal_error_has_no_stale_id() -> None:
    dev = FakeDevice(sign_errors=[th.HelperError("cancelled", "rejected on device")])
    rc, out = run(frame(hello()) + frame(sign(id=4)) + raw(b"["), dev)
    assert out[-2]["id"] == 4
    assert assert_fatal(rc, out)["id"] is None


@pytest.mark.parametrize("model", ["", "m" * 65, "Safe\n7", "Safe\x7f", "Safe 7\u00e4"])
def test_invalid_device_info_is_not_sent(model: str) -> None:
    rc, out = run(frame(hello()), FakeDevice(model=model))
    err = assert_fatal(rc, out, "device_error")
    assert err["message"] == "device reported an invalid model"
    assert [m["type"] for m in out] == ["error"]


def test_device_info_boundaries_accepted() -> None:
    for model in ["S", " " * 64, "~" * 64]:
        rc, out = run(frame(hello()), FakeDevice(model=model))
        assert rc == 0 and out[0]["device"]["model"] == model


@pytest.mark.parametrize(
    ("size", "ok"),
    [(1, True), (th.MAX_CREDENTIAL, True), (0, False), (th.MAX_CREDENTIAL + 1, False)],
)
def test_new_credential_size_checked_before_ready(size: int, ok: bool) -> None:
    dev = FakeDevice(new_credential=b"c" * size)
    rc, out = run(frame(hello(credential=None)) + code(PAIRING_CODE), dev)
    if ok:
        assert rc == 0 and base64.b64decode(out[-1]["credential"]) == b"c" * size
    else:
        assert_fatal(rc, out, "internal")
        assert "ready" not in [m["type"] for m in out]


@pytest.mark.parametrize(
    "msg",
    [
        hello(),
        {"type": "pairing_code", "code": "123456"},
        {"type": "event", "event": "button"},
        {"type": "x"},
        {},
    ],
)
def test_wrong_message_after_ready(msg: dict[str, Any]) -> None:
    assert_sign_rejected(msg)


# ---- HelperError -----------------------------------------------------------------------


def test_helper_error_invariants() -> None:
    assert len(th.HelperError("device_error", "x" * 1000).message) == th.MAX_MESSAGE
    for code in th.ALWAYS_FATAL:
        assert th.HelperError(code, "x").fatal is True
    for code in ("cancelled", "passphrase_unavailable", "device_error"):
        assert th.HelperError(code, "x").fatal is False


# ---- base64 / token properties ---------------------------------------------------------


def test_property_base64_accepts_exactly_canonical_encodings() -> None:
    rng = random.Random(2)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_ \n"
    for _ in range(3000):
        data = rng.randbytes(rng.randrange(40))
        enc = base64.b64encode(data).decode()
        assert th._base64(enc, "x", 40) == data
        if enc:
            pos = rng.randrange(len(enc))
            mutated = enc[:pos] + rng.choice(alphabet) + enc[pos + 1 :]
            try:
                decoded = th._base64(mutated, "x", 40)
            except th.HelperError:
                continue
            assert base64.b64encode(decoded).decode() == mutated  # only canonical forms pass
    with pytest.raises(th.HelperError):
        th._base64(base64.b64encode(b"x" * 41).decode(), "x", 40)


TOKEN_RE = re.compile(r"[\x21-\x2e\x30-\x39\x3b-\x3f\x41-\x7e]{1,128}")


def test_property_token_matches_spec_oracle() -> None:
    rng = random.Random(3)
    pool = [chr(c) for c in range(0x80)] + ["é", "\u202e", "\uff16", "\U0001f642"]
    for _ in range(5000):
        n = rng.choice([0, 1, 2, 5, 127, 128, 129])
        s = "".join(rng.choice(pool if rng.random() < 0.2 else pool[0x21:0x7F]) for _ in range(n))
        expected = TOKEN_RE.fullmatch(s) is not None
        try:
            th._token(s, "t")
            accepted = True
        except th.HelperError:
            accepted = False
        assert accepted == expected, repr(s)


# ---- credential blob -------------------------------------------------------------------


def test_property_credential_roundtrip() -> None:
    rng = random.Random(4)
    for _ in range(300):
        cred = th.PairingCredential(
            rng.randbytes(32), rng.randbytes(32), rng.randbytes(rng.randrange(1, 1025))
        )
        blob = cred.encode()
        assert blob == cred.trezor_pubkey + cred.host_privkey + cred.credential
        assert len(blob) <= th.MAX_CREDENTIAL
        assert th.PairingCredential.decode(blob) == cred


def test_property_credential_decode_never_raises() -> None:
    rng = random.Random(5)
    for _ in range(2000):
        blob = rng.randbytes(rng.randrange(1200))
        result = th.PairingCredential.decode(blob)
        assert (result is not None) == (65 <= len(blob) <= 64 + 1024)


@pytest.mark.parametrize(
    ("pub", "priv", "cred"),
    [(31, 32, 1), (33, 32, 1), (32, 31, 1), (32, 33, 1), (32, 32, 0), (32, 32, 1025)],
)
def test_credential_encode_rejects_wrong_sizes(pub: int, priv: int, cred: int) -> None:
    bad = th.PairingCredential(b"a" * pub, b"b" * priv, b"c" * cred)
    with pytest.raises(th.HelperError) as info:
        bad.encode()
    assert info.value.code == "pairing_failed" and info.value.fatal


@pytest.mark.parametrize("size", [0, 1, 64, 64 + 1025, 4096])
def test_credential_decode_rejects_wrong_sizes(size: int) -> None:
    assert th.PairingCredential.decode(b"\x05" * size) is None


def test_reprs_hide_secrets() -> None:
    secret = b"\xa7" * 32
    cred = th.PairingCredential(secret, secret, secret)
    texts = [
        repr(cred),
        repr(th.Hello("a", "b", "usb", secret)),
        repr(th.Ready("m", "i", "1.2.3", True, secret)),
        repr(
            th.SignRequest(
                1,
                identity(user=None),
                "ed25519",
                secret,
                "visual-secret",
                "ask",
            )
        ),
    ]
    for text in texts:
        assert "\\xa7" not in text and "p6en" not in text and "visual-secret" not in text


# ---- trezorlib error mapping (real exception classes, no device) -------------------------


def test_trezor_error_mapping() -> None:
    from trezorlib import exceptions as ex
    from trezorlib import messages
    from trezorlib.thp.exceptions import ThpError
    from trezorlib.transport import DeviceIsBusy, Timeout, TransportException

    def failure(code: messages.FailureType, text: str = "secret-text") -> ex.TrezorFailure:
        return ex.TrezorFailure(messages.Failure(code=code, message=text))

    cases: list[tuple[Exception, str, bool]] = [
        (ex.Cancelled(), "cancelled", False),
        (failure(messages.FailureType.ActionCancelled), "cancelled", False),
        (failure(messages.FailureType.PinCancelled), "cancelled", False),
        (failure(messages.FailureType.DataError), "device_error", False),
        (ex.PassphraseError("secret-text"), "passphrase_unavailable", False),
        (ex.DeviceLockedError(), "device_error", True),
        (ex.OutdatedFirmwareError(), "device_error", False),
        (ex.InvalidSessionError(1), "device_error", False),
        (TransportException("secret-text"), "device_error", True),
        (Timeout("secret-text"), "device_error", True),
        (DeviceIsBusy("secret-text"), "device_error", True),
        (ex.ProtocolError("secret-text"), "device_error", True),
        (ThpError(3), "device_error", True),
        (ex.TrezorException("secret-text"), "device_error", True),
        (OSError("secret-text"), "device_error", True),
        (RuntimeError("secret-text"), "internal", True),
        (KeyError("secret-text"), "internal", True),
    ]
    for exc, code, fatal in cases:
        err = th.trezor_error(exc)
        assert (err.code, err.fatal) == (code, fatal), exc
        assert "secret" not in err.message
    assert th.trezor_error(failure(messages.FailureType.DataError)).message.endswith("DataError")


def test_mapped_passes_helper_error_and_eof_through() -> None:
    err = th.HelperError("cancelled", "x")
    with pytest.raises(th.HelperError) as info, th._mapped():
        raise err
    assert info.value is err
    with pytest.raises(th.EndOfInput), th._mapped():
        raise th.EndOfInput
    with pytest.raises(th.HelperError) as info, th._mapped():
        raise ValueError("secret")
    assert info.value.code == "internal"


# ---- transport selection (enumeration stubbed, no hardware) ------------------------------


@pytest.fixture
def transports(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    from trezorlib.transport.ble import BleTransport
    from trezorlib.transport.webusb import WebUsbTransport

    state: dict[str, Any] = {"usb": [], "ble": [], "calls": []}

    def fake(kind: str) -> Any:
        def enumerate_(*_args: Any, **_kw: Any) -> list[Any]:
            state["calls"].append(kind)
            result = state[kind]
            if isinstance(result, BaseException):
                raise result
            if callable(result):
                return result()
            return list(result)

        return classmethod(lambda cls, *a, **k: enumerate_(*a, **k))

    monkeypatch.setattr(WebUsbTransport, "enumerate", fake("usb"))
    monkeypatch.setattr(BleTransport, "enumerate", fake("ble"))
    monkeypatch.setattr(WebUsbTransport, "ENABLED", True)
    monkeypatch.setattr(BleTransport, "ENABLED", True)
    return state


@pytest.mark.parametrize(
    ("kind", "usb", "ble", "expected", "calls"),
    [
        ("usb", ["U"], ["B"], "U", ["usb"]),
        ("ble", ["U"], ["B"], "B", ["ble"]),
        ("auto", ["U"], ["B"], "U", ["usb"]),
        ("auto", [], ["B"], "B", ["usb", "ble"]),
        ("auto", RuntimeError("no libusb"), ["B"], "B", ["usb", "ble"]),
        ("usb", [], ["B"], None, ["usb"]),
        ("ble", ["U"], [], None, ["ble"]),
        ("ble", ["U"], RuntimeError("bluetooth off"), None, ["ble"]),
        ("auto", [], [], None, ["usb", "ble"]),
        ("usb", ["U1", "U2"], [], "many", ["usb"]),
        ("ble", [], ["B1", "B2"], "many", ["ble"]),
        ("auto", ["U1", "U2"], ["B"], "many", ["usb"]),
        ("auto", [], ["B1", "B2"], "many", ["usb", "ble"]),
    ],
)
def test_find_transport(
    transports: dict[str, Any],
    kind: str,
    usb: Any,
    ble: Any,
    expected: str | None,
    calls: list[str],
) -> None:
    transports.update(usb=usb, ble=ble)
    if expected is None:
        with pytest.raises(th.HelperError) as info:
            th.find_transport(kind)
        assert info.value.code == "device_not_found" and info.value.fatal
    elif expected == "many":
        with pytest.raises(th.HelperError) as info:
            th.find_transport(kind)
        assert (info.value.code, info.value.fatal) == ("device_error", True)
        assert info.value.message == "more than one Trezor found; connect only one"
    else:
        assert th.find_transport(kind) == expected
    assert transports["calls"] == calls


def test_ble_disabled_means_not_found(
    transports: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from trezorlib.transport.ble import BleTransport

    monkeypatch.setattr(BleTransport, "ENABLED", False)
    transports["ble"] = ["B"]
    with pytest.raises(th.HelperError):
        th.find_transport("ble")
    assert transports["calls"] == []


def test_ble_scan_is_bounded(transports: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(th, "BLE_SCAN_TIMEOUT", 0.3)
    transports["ble"] = lambda: time.sleep(30)  # e.g. macOS permission prompt never answered
    previous = signal.getsignal(signal.SIGALRM)
    start = time.monotonic()
    with pytest.raises(th.HelperError) as info:
        th.find_transport("auto")
    assert time.monotonic() - start < 5
    assert info.value.code == "device_not_found"
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_ble_scan_timer_cancelled_after_success(transports: dict[str, Any]) -> None:
    transports["ble"] = ["B"]
    previous = signal.getsignal(signal.SIGALRM)
    assert th.find_transport("ble") == "B"
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    assert signal.getsignal(signal.SIGALRM) == previous


def test_stop_ble_kills_the_proxy_process(monkeypatch: pytest.MonkeyPatch) -> None:
    from trezorlib.transport.ble import BleTransport

    proc = multiprocessing.get_context("spawn").Process(target=time.sleep, args=(60,), daemon=True)
    proc.start()
    proxy = SimpleNamespace(process=proc, pipe=object())
    monkeypatch.setattr(BleTransport, "_ble", proxy)
    start = time.monotonic()
    th.stop_ble()
    assert time.monotonic() - start < 5
    assert not proc.is_alive() and proc.exitcode == -signal.SIGKILL
    assert proxy.process is None and proxy.pipe is None
    th.stop_ble()  # idempotent


def test_stop_ble_without_proxy_is_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    from trezorlib.transport.ble import BleTransport

    monkeypatch.setattr(BleTransport, "_ble", None)
    th.stop_ble()
    monkeypatch.delitem(sys.modules, "trezorlib.transport.ble")
    th.stop_ble()


# ---- TrezorDevice glue with a stub client (no hardware) ----------------------------------


class StubSession:
    def __init__(self, passphrase: Any) -> None:
        self.passphrase = passphrase
        self.closed = False

    def close(self) -> None:
        self.closed = True


class StubPairing:
    def __init__(self, paired: bool, methods: Any = ()) -> None:
        self.paired = paired
        self.methods = methods
        self.credential_requests: list[bool] = []
        self.finished = False

    def is_paired(self) -> bool:
        return self.paired

    def request_credential(self, autoconnect: bool = True) -> Any:
        self.credential_requests.append(autoconnect)
        return CREDENTIAL

    def finish(self) -> None:
        self.finished = True


class StubFeatures:
    initialized = True
    passphrase_protection = True
    internal_model = "T3W1"
    major_version, minor_version, patch_version = 2, 13, 1


class StubModel:
    name = "Safe 7"
    internal_name = "T3W1"


class StubClient:
    def __init__(self, app: Any, pairing: StubPairing) -> None:
        self.app = app
        self.pairing = pairing
        self.features = StubFeatures()
        self.model = StubModel()
        self.sessions: list[StubSession] = []
        self.unlocked = False

    def connect(self) -> None:
        pass

    def ensure_unlocked(self) -> None:
        self.unlocked = True

    def get_session(self, passphrase: Any) -> StubSession:
        self.sessions.append(StubSession(passphrase))
        return self.sessions[-1]


class RecordingUi:
    def __init__(self) -> None:
        self.events: list[str] = []

    def button(self) -> None:
        self.events.append("button")

    def pairing_code(self) -> str:
        self.events.append("code")
        return PAIRING_CODE


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import trezorlib.client
    import trezorlib.misc
    import trezorlib.thp.client
    import trezorlib.thp.pairing

    state: dict[str, Any] = {"pairing": StubPairing(paired=True), "signed": []}

    def get_client(app: Any, transport: Any) -> StubClient:
        state["client"] = StubClient(app, state["pairing"])
        return state["client"]

    class StubCodeEntry:
        def __init__(self, pairing: StubPairing) -> None:
            state["code_entry"] = self

        def send_code(self, code: str) -> None:
            state["code"] = code
            state["pairing"].paired = True

    def sign_identity(session: Any, ident: Any, hidden: bytes, visual: str, curve: str) -> Any:
        state["signed"].append((session, ident, hidden, visual, curve))
        if state.get("sign_error"):
            raise state["sign_error"]
        return type("Signed", (), {"public_key": b"\x00pub", "signature": b"\x00sig"})()

    monkeypatch.setattr(th, "find_transport", lambda kind: f"transport:{kind}")
    monkeypatch.setattr(trezorlib.client, "get_client", get_client)
    monkeypatch.setattr(trezorlib.thp.pairing, "CodeEntry", StubCodeEntry)
    monkeypatch.setattr(trezorlib.misc, "sign_identity", sign_identity)
    monkeypatch.setattr(trezorlib.thp.client, "TrezorClientThp", StubClient)
    state["CodeEntry"] = StubCodeEntry
    return state


def make_hello(cred: bytes | None) -> th.Hello:
    return th.Hello("petschaft", "mac", "ble", cred)


def test_trezor_device_open_with_known_credential(stub: dict[str, Any]) -> None:
    ui = RecordingUi()
    ready = th.TrezorDevice().open(make_hello(CREDENTIAL.encode()), ui)
    assert ready == th.Ready("Safe 7", "T3W1", "2.13.1", True, None)
    app = stub["client"].app
    assert (app.app_name, app.host_name) == ("petschaft", "mac")
    assert list(app.get_credentials()) == [CREDENTIAL]
    assert stub["client"].unlocked and ui.events == []
    app.button_callback(object())
    assert ui.events == ["button"]


def test_trezor_device_open_pairs_and_requests_normal_credential(stub: dict[str, Any]) -> None:
    stub["pairing"] = StubPairing(paired=False, methods={stub["CodeEntry"]})
    ui = RecordingUi()
    ready = th.TrezorDevice().open(make_hello(b"garbage"), ui)
    assert list(stub["client"].app.get_credentials()) == []
    assert ui.events == ["code"] and stub["code"] == PAIRING_CODE
    assert stub["pairing"].credential_requests == [False]  # never autoconnect
    assert stub["pairing"].finished
    assert ready.credential == CREDENTIAL.encode()


def test_trezor_device_rejects_protocol_v1_client(
    stub: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import trezorlib.thp.client
    from trezorlib.protocol_v1 import TrezorClientV1

    assert not issubclass(TrezorClientV1, trezorlib.thp.client.TrezorClientThp)
    # get_client now returns a client that is not a TrezorClientThp, as for protocol v1.
    monkeypatch.setattr(trezorlib.thp.client, "TrezorClientThp", type("Thp", (), {}))
    with pytest.raises(th.HelperError) as info:
        th.TrezorDevice().open(make_hello(None), RecordingUi())
    assert (info.value.code, info.value.fatal) == ("device_error", True)
    assert info.value.message == "device does not support THP"
    assert stub["pairing"].credential_requests == []


def test_trezor_device_open_without_code_entry_fails(stub: dict[str, Any]) -> None:
    stub["pairing"] = StubPairing(paired=False, methods=set())
    with pytest.raises(th.HelperError) as info:
        th.TrezorDevice().open(make_hello(None), RecordingUi())
    assert info.value.code == "pairing_failed"


def test_trezor_device_open_not_initialized(
    stub: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(StubFeatures, "initialized", False)
    with pytest.raises(th.HelperError) as info:
        th.TrezorDevice().open(make_hello(CREDENTIAL.encode()), RecordingUi())
    assert info.value.code == "device_not_initialized"


def sign_request(passphrase: str) -> th.SignRequest:
    ident = identity(proto="gpg", user="u", host="h", port="22", path="/p", index=7)
    return th.SignRequest(1, ident, "nist256p1", b"\x01" * 32, "visual", passphrase)


def test_trezor_device_standard_session_is_reused(stub: dict[str, Any]) -> None:
    from trezorlib.client import PassphraseSetting

    dev = th.TrezorDevice()
    dev.open(make_hello(CREDENTIAL.encode()), RecordingUi())
    assert dev.sign(sign_request("standard")) == (b"\x00pub", b"\x00sig")
    dev.sign(sign_request("standard"))
    sessions = stub["client"].sessions
    assert [s.passphrase for s in sessions] == [PassphraseSetting.STANDARD_WALLET]
    session, ident, hidden, visual, curve = stub["signed"][0]
    assert session is sessions[0] and (hidden, visual, curve) == (
        b"\x01" * 32,
        "visual",
        "nist256p1",
    )
    assert (ident.proto, ident.user, ident.host, ident.port, ident.path, ident.index) == (
        "gpg",
        "u",
        "h",
        "22",
        "/p",
        7,
    )


def test_trezor_device_error_drops_standard_session(stub: dict[str, Any]) -> None:
    from trezorlib import exceptions as ex

    dev = th.TrezorDevice()
    dev.open(make_hello(CREDENTIAL.encode()), RecordingUi())
    stub["sign_error"] = ex.Cancelled()
    with pytest.raises(th.HelperError) as info:
        dev.sign(sign_request("standard"))
    assert info.value.code == "cancelled" and not info.value.fatal
    stub["sign_error"] = None
    dev.sign(sign_request("standard"))
    assert len(stub["client"].sessions) == 2


def test_trezor_device_ask_uses_new_closed_session_each_time(stub: dict[str, Any]) -> None:
    from trezorlib.client import PassphraseSetting

    dev = th.TrezorDevice()
    dev.open(make_hello(CREDENTIAL.encode()), RecordingUi())
    dev.sign(sign_request("ask"))
    dev.sign(sign_request("ask"))
    sessions = stub["client"].sessions
    assert [s.passphrase for s in sessions] == [PassphraseSetting.ON_DEVICE] * 2
    assert all(s.closed for s in sessions)


def test_trezor_device_ask_without_passphrase_protection(
    stub: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(StubFeatures, "passphrase_protection", False)
    dev = th.TrezorDevice()
    dev.open(make_hello(CREDENTIAL.encode()), RecordingUi())
    with pytest.raises(th.HelperError) as info:
        dev.sign(sign_request("ask"))
    assert info.value.code == "passphrase_unavailable" and not info.value.fatal
    assert stub["client"].sessions == []


# ---- end to end: real subprocess, real stdout isolation ---------------------------------


def spawn(script: str, *args: str, data: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", str(HERE / script), *args],
        input=data,
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_e2e_pairing_and_signing() -> None:
    data = frame(hello(credential=None)) + code(PAIRING_CODE) + frame(sign(id=1))
    proc = spawn("fake_helper.py", "default", data=data)
    assert proc.returncode == 0, proc.stderr
    out = parse_frames(proc.stdout)
    assert [m.get("event", m["type"]) for m in out] == [
        "button",
        "pairing_code_required",
        "ready",
        "button",
        "signed",
    ]


def test_e2e_only_frames_reach_stdout() -> None:
    proc = spawn("fake_helper.py", "noisy", data=frame(hello()) + frame(sign()))
    assert proc.returncode == 0
    assert [m["type"] for m in parse_frames(proc.stdout)] == ["ready", "event", "signed"]
    for where in ("open", "sign"):
        for how in ("print", "fd 1", "child", "mp child", "mp child fd 1"):
            assert f"noise: {how} in {where}".encode() in proc.stderr
    # multiprocessing children are spawned, so they do not inherit the frame pipe
    assert b"noise: start method spawn" in proc.stderr
    assert b"holds the frame pipe" not in proc.stderr


def test_e2e_fatal_exits_1() -> None:
    proc = spawn("fake_helper.py", "default", data=frame(hello()) + raw(b"[]"))
    assert proc.returncode == 1
    out = parse_frames(proc.stdout)
    assert out[-1]["code"] == "bad_request" and out[-1]["fatal"] is True


def test_e2e_internal_error_does_not_leak() -> None:
    proc = spawn("fake_helper.py", "crash", data=frame(hello()) + frame(sign()))
    assert proc.returncode == 1
    assert parse_frames(proc.stdout)[-1]["code"] == "internal"
    assert b"secret detail" not in proc.stdout + proc.stderr


def test_e2e_cancel_is_not_fatal() -> None:
    proc = spawn(
        "fake_helper.py", "cancel-once", data=frame(hello()) + frame(sign(id=1)) + frame(sign(id=2))
    )
    assert proc.returncode == 0
    out = [m for m in parse_frames(proc.stdout) if m["type"] in ("error", "signed")]
    assert [(m["type"], m["id"]) for m in out] == [("error", 1), ("signed", 2)]


def test_e2e_production_entry_point_eof_and_validation() -> None:
    # Touches no hardware: EOF before hello, and a hello rejected before any device access.
    proc = spawn("petschaft_helper.py", data=b"")
    assert (proc.returncode, proc.stdout) == (0, b"")
    proc = spawn("petschaft_helper.py", data=frame(hello(version=2)))
    assert proc.returncode == 1
    assert assert_fatal(1, parse_frames(proc.stdout))["id"] is None


def test_production_entry_point_has_no_injection_switch() -> None:
    source = (HERE / "petschaft_helper.py").read_text()
    for needle in ("environ", "getenv", "argv", "fake_helper", "input("):
        assert needle not in source
    assert source.rstrip().endswith('if __name__ == "__main__":\n    sys.exit(main())')
