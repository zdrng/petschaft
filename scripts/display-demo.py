"""Show petschaft's three confirmation screens on the Trezor, for README photos.

Sends one SignIdentity request per scenario with exactly the text `pets` shows:
  1. git commit   "commit: Fix login"
  2. SSH login    "ssh login user (desktop) 3fa9c21e"
  3. APK          "apk v3 org.example.app:1.4.2(42) 3fa9c21e"
Photograph each screen, then REJECT it on the device.

Harmless even if confirmed by mistake: demo identities (ssh://demo@..., gpg://demo@...)
that are not your keys, and random challenges that are no commit, login or APK.
Nothing is stored (no pairing credential, no files), so the Trezor asks for the
pairing code once at the start.

Run from the repository root:
  nix develop -c python3 -I scripts/display-demo.py          # Bluetooth
  nix develop -c python3 -I scripts/display-demo.py usb      # cable
"""

from __future__ import annotations

import hashlib
import os
import sys

from trezorlib import messages, misc
from trezorlib.client import AppManifest, PassphraseSetting, get_client
from trezorlib.exceptions import Cancelled
from trezorlib.thp.pairing import CodeEntry
from trezorlib.transport.ble import BleTransport
from trezorlib.transport.webusb import WebUsbTransport

SCENARIOS = [
    ("git commit", "ssh", "demo", "git", "ed25519", "commit: Fix login"),
    ("SSH login", "ssh", "demo", "desktop", "ed25519", "ssh login user (desktop) 3fa9c21e"),
    ("APK", "gpg", "demo", "apk-release", "nist256p1", "apk v3 org.example.app:1.4.2(42) 3fa9c21e"),
]


def transport(kind: str):
    cls = WebUsbTransport if kind == "usb" else BleTransport
    found = list(cls.enumerate())
    if len(found) != 1:
        sys.exit(f"expected exactly one Trezor via {kind}, found {len(found)}")
    return found[0]


def main() -> None:
    kind = sys.argv[1] if len(sys.argv) > 1 else "ble"
    if kind not in ("ble", "usb"):
        sys.exit("usage: display-demo.py [ble|usb]")
    print(f"Connecting via {kind} ... (unlock the Trezor)")
    app = AppManifest(app_name="petschaft-demo", button_callback=lambda _msg: None)
    client = get_client(app, transport(kind))
    if not client.pairing.is_paired():
        client.pairing.client.connect()
        method = CodeEntry(client.pairing)
        method.send_code(input("Pairing code shown on the Trezor: ").strip())
        client.pairing.finish()
    session = client.get_session(passphrase=PassphraseSetting.STANDARD_WALLET)

    for n, (title, proto, user, host, curve, visual) in enumerate(SCENARIOS, 1):
        input(f"\n[{n}/3] {title}: press Enter, photograph the screen, then REJECT it ")
        identity = messages.IdentityType(proto=proto, user=user, host=host, index=0)
        challenge = os.urandom(32)
        if proto == "gpg":
            challenge = hashlib.sha256(challenge).digest()
        try:
            misc.sign_identity(session, identity, challenge, visual, curve)
            print("   confirmed (harmless: demo identity, random data)")
        except Cancelled:
            print("   rejected - good")
    print("\nDone. Nothing was stored.")


if __name__ == "__main__":
    main()
