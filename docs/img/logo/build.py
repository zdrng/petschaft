"""Build the petschaft logo variants (SVG), the comparison sheet and the README icon.

Python stdlib only and deterministic (fixed number formatting, no timestamps). Writes SVG only;
`nix build .#readme-logos` renders every SVG to PNG with resvg and the Inter font from nixpkgs
(see flake.nix) and drops the two helper SVGs. Update the committed files from the repository
root with:

    nix build .#readme-logos -o result-logo
    install -m 644 result-logo/* docs/img/logo/ && rm result-logo

Usage: python3 -I build.py <output-dir>
Writes variant-{a,b}.svg (1024x1024, full-bleed black), comparison.svg (1400x1200) and
readme-icon.svg (the DEFAULT variant in a squircle, 240x240 for a 120 px README image).
"""

from __future__ import annotations

import math
import sys
from collections.abc import Callable
from pathlib import Path

DEFAULT = "b"  # chosen variant: README icon and the "recommended" label on the sheet

BLACK, WHITE = "#000000", "#FFFFFF"
G1, G2, G3 = "#93969A", "#6A6B6D", "#2E2F30"
CYAN = "#62E6DC"  # the "Confirm" cyan of the device screens (docs/img/render.py)
SHEET_BG = "#1A1A1A"
FONT = "Inter"


def n(v: float) -> str:
    """Fixed, short number formatting (deterministic output)."""
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s == "-0" else s


def circle(cx: float, cy: float, r: float, fill: str) -> str:
    return f'<circle cx="{n(cx)}" cy="{n(cy)}" r="{n(r)}" fill="{fill}"/>'


def ring(cx: float, cy: float, r: float, width: float, stroke: str) -> str:
    return (
        f'<circle cx="{n(cx)}" cy="{n(cy)}" r="{n(r)}" fill="none" '
        f'stroke="{stroke}" stroke-width="{n(width)}"/>'
    )


def line(x1: float, y1: float, x2: float, y2: float, width: float, stroke: str) -> str:
    return (
        f'<line x1="{n(x1)}" y1="{n(y1)}" x2="{n(x2)}" y2="{n(y2)}" stroke="{stroke}" '
        f'stroke-width="{n(width)}" stroke-linecap="round"/>'
    )


def centered(parts: list[str], cx: float, cy: float, scale: float = 1.0) -> str:
    """Move a mark whose bounding box centre is (cx, cy) to the canvas centre and scale it."""
    body = "\n    ".join(parts)
    t = f"translate(512 512) scale({n(scale)}) translate({n(-cx)} {n(-cy)})"
    return f'<g transform="{t}">\n    {body}\n  </g>'


# ---------------------------------------------------------------- variant A: Sealed commit
# A commit history: a grey line through two older commits (dark grey, light grey) to the
# newest commit, a white node inside a cyan ring: this commit carries a signature.
def sealed_commit() -> str:
    y = 512
    x1, x2, x3 = 176, 392, 688  # older, old, newest
    r_node = 64
    r_ring, w_ring = 158, 44  # ring centre line and stroke: outer 180, inner 136
    parts = [
        line(x1, y, x3, y, 44, G2),
        # black gap between the white node and the ring, also cuts the line
        circle(x3, y, r_ring - w_ring / 2, BLACK),
        ring(x3, y, r_ring, w_ring, CYAN),
        circle(x3, y, 96, WHITE),
        circle(x1, y, r_node, G2),
        circle(x2, y, r_node, G1),
    ]
    left, right = x1 - r_node, x3 + r_ring + w_ring / 2
    return centered(parts, (left + right) / 2, y, 0.9)


# ---------------------------------------------------------------- variant B: Signet p
# A geometric lowercase "p": a white stem and a ring for the bowl. Seen from above, the bowl
# is the face of a signet (German "Petschaft"); the cyan dot inside is the imprint, the one
# press on the device that seals the signature.
def signet_p() -> str:
    w = 108  # stroke weight of stem and ring
    sx = 392  # stem centre line
    rc = 150  # ring centre line radius
    cx, cy = sx + rc, 462  # the ring's left stroke coincides with the stem
    top, bottom = cy - rc - w / 2, 812  # flat top at x-height, round foot
    stem = (
        f"M{n(sx - w / 2)},{n(top)} H{n(sx + w / 2)} V{n(bottom)} "
        f"A{n(w / 2)},{n(w / 2)} 0 0 1 {n(sx - w / 2)},{n(bottom)} Z"
    )
    parts = [
        f'<path d="{stem}" fill="{WHITE}"/>',
        ring(cx, cy, rc, w, WHITE),
        circle(cx, cy, 54, CYAN),
    ]
    left, right = sx - w / 2, cx + rc + w / 2
    return centered(parts, (left + right) / 2, (top + bottom + w / 2) / 2)


VARIANTS: list[tuple[str, str, str, Callable[[], str]]] = [
    ("a", "A", "Sealed commit", sealed_commit),
    ("b", "B", "Signet p", signet_p),
]


def icon_body(mark: str) -> str:
    return f'<rect width="1024" height="1024" fill="{BLACK}"/>\n  {mark}'


def icon_svg(mark: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" '
        f'width="1024" height="1024">\n  {icon_body(mark)}\n</svg>\n'
    )


def nested(mark: str, x: float, y: float, size: float) -> str:
    return (
        f'<svg x="{n(x)}" y="{n(y)}" width="{n(size)}" height="{n(size)}" '
        f'viewBox="0 0 1024 1024">{icon_body(mark)}</svg>'
    )


def squircle(x: float, y: float, s: float, e: float = 5.0, steps: int = 240) -> str:
    """Superellipse path approximating the iOS squircle."""
    c = s / 2
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        ct, st = math.cos(t), math.sin(t)
        px = c + c * math.copysign(abs(ct) ** (2 / e), ct)
        py = c + c * math.copysign(abs(st) ** (2 / e), st)
        pts.append(f"{n(x + px)},{n(y + py)}")
    return "M" + " L".join(pts) + " Z"


def in_squircle(cid: str, mark: str, x: float, y: float, size: float) -> str:
    return (
        f'<clipPath id="{cid}"><path d="{squircle(x, y, size)}"/></clipPath>\n'
        f'  <g clip-path="url(#{cid})">{nested(mark, x, y, size)}</g>'
    )


def sheet(marks: dict[str, str]) -> str:
    W, H, big = 1400, 1200, 480
    gap = (W - len(VARIANTS) * big) / (len(VARIANTS) + 1)
    parts = []
    for i, (k, letter, name, _) in enumerate(VARIANTS):
        x, y = gap + i * (big + gap), 110
        label = name + (" · chosen" if k == DEFAULT else "")
        parts.append(
            in_squircle(f"big{k}", marks[k], x, y, big)
            + f'\n  <text x="{n(x + big / 2)}" y="{n(y + big + 78)}" text-anchor="middle" '
            f'font-family="{FONT}" font-size="56" font-weight="700" fill="{WHITE}">{letter}</text>'
            + f'\n  <text x="{n(x + big / 2)}" y="{n(y + big + 124)}" text-anchor="middle" '
            f'font-family="{FONT}" font-size="30" fill="{G1}">{label}</text>'
        )
        sx, sy = x + big / 2 - (120 + 40 + 60) / 2, 900
        parts.append(in_squircle(f"sm{k}", marks[k], sx, sy, 120))
        parts.append(in_squircle(f"xs{k}", marks[k], sx + 160, sy + 30, 60))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">\n'
        f'  <rect width="{W}" height="{H}" fill="{SHEET_BG}"/>\n  '
        + "\n  ".join(parts)
        + f'\n  <line x1="{n(gap)}" y1="850" x2="{n(W - gap)}" y2="850" stroke="{G3}" stroke-width="2"/>'
        + f'\n  <text x="{n(gap)}" y="1100" font-family="{FONT}" font-size="24" fill="{G2}">'
        "petschaft logo variants · 120 px and 60 px previews</text>\n</svg>\n"
    )


def readme_icon(mark: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 240" width="240" height="240">\n  '
        + in_squircle("icon", mark, 0, 0, 240)
        + "\n</svg>\n"
    )


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: build.py <output-dir>")
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    marks = {k: fn() for k, _, _, fn in VARIANTS}
    for k, mark in marks.items():
        (out / f"variant-{k}.svg").write_text(icon_svg(mark))
    (out / "comparison.svg").write_text(sheet(marks))
    (out / "readme-icon.svg").write_text(readme_icon(marks[DEFAULT]))


if __name__ == "__main__":
    main()
