"""TEST ONLY: a fake device for the helper tests, and a subprocess entry point using it.

`python3 -I helper/fake_helper.py [scenario]` runs the real `petschaft_helper.main` (including
the stdout isolation) with a `FakeDevice`. The production entry point (`petschaft_helper.py`)
never imports this module and honors no flag or environment variable that selects it.

The fake signs for real, with one fixed key per curve, in the device formats and over
the data the firmware signs (ssh/ed25519 and gpg/ed25519: the raw challenge;
ssh/nist256p1: SHA-256 of the challenge; gpg/nist256p1: the 32-byte challenge as digest),
so the Rust end-to-end test (`crates/petschaft-device/tests/e2e_helper.rs`) can verify them.
"""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent))  # `-I` implies `-P`
import petschaft_helper as th

PAIRING_CODE = "620567"
CREDENTIAL = th.PairingCredential(b"\x01" * 32, b"\x02" * 32, b"fake-credential")
ED25519_SEED = bytes(range(32))  # same keys in e2e_helper.rs
P256_SCALAR = int.from_bytes(bytes(range(1, 33)), "big")
CANCEL_VISUAL = "fake: reject"  # a sign request with this text is "rejected on the device"


def fake_signature(req: th.SignRequest) -> tuple[bytes, bytes]:
    data = req.challenge_hidden
    if req.curve == "ed25519":
        key = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_SEED)
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return b"\x00" + pub, b"\x00" + key.sign(data)
    p256 = ec.derive_private_key(P256_SCALAR, ec.SECP256R1())
    digest = data if req.identity["proto"] == "gpg" else hashlib.sha256(data).digest()
    r, s = decode_dss_signature(p256.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
    pub = p256.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return pub, b"\x00" + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def mp_noise(where: str, frame_pipe: tuple[int, int]) -> None:
    """Runs in a multiprocessing child, like trezorlib's BLE proxy."""
    print(f"noise: mp child in {where}")
    os.write(1, f"noise: mp child fd 1 in {where}\n".encode())
    for fd in range(256):
        with suppress(OSError):
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) == frame_pipe:
                print(f"noise: mp child holds the frame pipe in {where}")


class FakeDevice:
    """Pairs when the hello carries no valid CREDENTIAL; signs with fixed keys."""

    def __init__(
        self,
        *,
        initialized: bool = True,
        passphrase_protection: bool = True,
        noisy: bool = False,
        sign_errors: list[Exception] | None = None,
        model: str = "Safe 7",
        new_credential: bytes = CREDENTIAL.encode(),
    ) -> None:
        self.initialized = initialized
        self.passphrase_protection = passphrase_protection
        self.noisy = noisy
        self.sign_errors = list(sign_errors or [])
        self.model = model
        self.new_credential = new_credential
        self.hellos: list[th.Hello] = []
        self.requests: list[th.SignRequest] = []
        self.ui: th.Server | None = None

    def _noise(self, where: str) -> None:
        if self.noisy:  # everything a library or child process might print
            print(f"noise: print in {where}")
            os.write(1, f"noise: fd 1 in {where}\n".encode())
            subprocess.run(
                [sys.executable, "-I", "-c", f"print('noise: child in {where}')"], check=True
            )
            assert self.ui is not None
            st = os.fstat(self.ui._tx.fileno())
            print(f"noise: start method {multiprocessing.get_start_method()}")
            child = multiprocessing.Process(target=mp_noise, args=(where, (st.st_dev, st.st_ino)))
            child.start()
            child.join()

    def open(self, hello: th.Hello, ui: th.Server) -> th.Ready:
        self.hellos.append(hello)
        self.ui = ui
        self._noise("open")
        new = None
        if hello.credential is None or th.PairingCredential.decode(hello.credential) != CREDENTIAL:
            ui.button()  # "pair with this app?"
            if ui.pairing_code() != PAIRING_CODE:
                raise th.HelperError("pairing_failed", "wrong pairing code")
            new = self.new_credential
        if not self.initialized:
            raise th.HelperError("device_not_initialized", "device has no seed")
        return th.Ready(self.model, "T3W1", "2.13.1", self.passphrase_protection, new)

    def sign(self, request: th.SignRequest) -> tuple[bytes, bytes]:
        self.requests.append(request)
        self._noise("sign")
        if request.passphrase == "ask" and not self.passphrase_protection:  # noqa: S105
            raise th.HelperError("passphrase_unavailable", "passphrase protection is disabled")
        assert self.ui is not None
        self.ui.button()
        if self.sign_errors:
            raise self.sign_errors.pop(0)
        if request.challenge_visual == CANCEL_VISUAL:
            raise th.HelperError("cancelled", "rejected on device")
        return fake_signature(request)


SCENARIOS = {
    "default": {},
    "noisy": {"noisy": True},
    "uninitialized": {"initialized": False},
    "cancel-once": {"sign_errors": [th.HelperError("cancelled", "rejected on device")]},
    "crash": {"sign_errors": [RuntimeError("secret detail that must not leak")]},
}

if __name__ == "__main__":
    sys.exit(th.main(FakeDevice(**SCENARIOS[sys.argv[1] if len(sys.argv) > 1 else "default"])))
