"""Render the README illustrations as SVG (terminal on the left, device on the right).

Deterministic: Python stdlib only, no timestamps, fixed ordering and number formatting,
so the same input always gives byte-identical SVGs. Text stays real SVG <text> in the
fonts Inter (sans) and JetBrains Mono NL (mono, no ligatures); `nix build
.#readme-images` renders the PNGs (2x) with resvg using exactly those font files from
nixpkgs (see flake.nix). Update the committed PNGs from the repository root with:

    nix build .#readme-images -o result-img && install -m 644 result-img/*.png docs/img/

The device is a stylized, logo-free drawing of a hardware wallet with a touch screen;
the screen text is exactly what `pets` sends to the Trezor.

Usage: python3 -I render.py <output-dir>
Writes <scene>.svg (dark theme) for the scenes git, ssh and apk.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from xml.sax.saxutils import escape

# Canvas (SVG user units; PNGs are rendered at 2x).
WIDTH = 920
HEIGHT = 480

SANS = "Inter"
MONO = "JetBrains Mono NL"  # the variant without ligatures: `->` stays two characters
MONO_ADVANCE = 0.6  # every glyph is 600/1000 em wide

# Terminal panel.
TERM_X = 16
TERM_W = 584
TERM_FONT = 13.5
TERM_LINE = 21.0
TERM_PAD_X = 22
TERM_BAR = 34

THEMES = {
    "dark": {
        "bg": "#0d1117",
        "border": "#30363d",
        "bar": "#161b22",
        "dot": "#30363d",
        "title": "#8b949e",
        "text": "#e6edf3",
        "dim": "#6e7681",
        "prompt": "#58a6ff",
        "accent": "#56d4e6",
        "rule": "#21262d",
        "cursor": "#e6edf3",
        "shadow": 0.0,
    },
}

# Device screen colors (identical in both variants).
SCREEN_TITLE = "#7fb2ff"
SCREEN_TEXT = "#7fe3f5"
SCREEN_ID = "#b8f1fb"
SCREEN_CONFIRM = "#62e6dc"

# Scenes. Terminal lines are (style, text); styles: cmd, out, dim, accent, rule, cursor.
# The text is what `pets` prints (crates/petschaft/src/{git,agent,apk,main}.rs); the
# "connected: ..." line printed before each signature is left out.
HOST_FP = "SHA256:3fa9c21eQk7Vb2mT0yXn5LpR8sWd4HjZcA1uEoGiNfM"
# apk.rs: the line before each of the two confirmations (v2, then v3).
APK_SAYS = (
    'pets: signing app-unsigned.apk with "apk-release" (confirmation {} of 2); the Trezor shows:'
)
APK_SHOWN = "apk v3 org.example.app:1.4.2(42) 3fa9c21e"

SCENES = [
    {
        "name": "git",
        "title": "~/src/app",
        "lines": [
            ("cmd", 'git commit -m "Fix login"'),
            ("dim", "connected: Safe 7 (T3W1), firmware 2.13.1"),
            ("out", "pets: signing commit: Fix login (identity git)"),
            ("accent", "  -> confirm on the Trezor ..."),
            ("cursor", ""),
        ],
        "device": ("Sign SSH", "commit: Fix login", "demo@git"),
    },
    {
        "name": "ssh",
        "title": "~",
        "lines": [
            ("cmd", "ssh desktop"),
            ("cursor", ""),
            ("rule", "pets agent log"),
            (
                "out",
                f"pets agent: sign request: ssh login user (desktop) 3fa9c21e, host key {HOST_FP}",
            ),
            ("accent", "pets agent: confirm on the Trezor ..."),
        ],
        "device": ("Sign SSH", "ssh login user (desktop) 3fa9c21e", "demo@desktop"),
    },
    {
        "name": "apk",
        "title": "~/src/app",
        "lines": [
            ("cmd", "pets apk sign apk-release app-unsigned.apk -o app.apk"),
            ("dim", APK_SAYS.format(1)),
            ("dim", "  apk v2 org.example.app:1.4.2(42) 3fa9c21e"),
            ("dim", "  -> confirm on the Trezor ..."),
            ("out", APK_SAYS.format(2)),
            ("out", f"  {APK_SHOWN}"),
            ("accent", "  -> confirm on the Trezor ..."),
        ],
        "device": ("Sign GPG", APK_SHOWN, "demo@apk-release"),
    },
]


def num(v: float) -> str:
    """Fixed-precision number: at most two decimals, no trailing zeros."""
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s == "-0" else s


def wrap_words(text: str, fits: Callable[[str], bool]) -> list[str]:
    """Greedy word wrap; a word that does not fit on its own is split by characters."""
    lines: list[str] = []
    current = ""
    for word in text.split(" "):
        candidate = word if not current else f"{current} {word}"
        if fits(candidate):
            current = candidate
            continue
        if current:
            lines.append(current)
        current = word
        while not fits(current):
            cut = len(current)
            while cut > 1 and not fits(current[:cut]):
                cut -= 1
            lines.append(current[:cut])
            current = current[cut:]
    lines.append(current)
    return lines


def wrap_mono(text: str, cols: int) -> list[str]:
    """Wrap terminal text at `cols` columns, keeping leading indentation."""
    indent = len(text) - len(text.lstrip(" "))
    body = wrap_words(text.lstrip(" "), lambda s: len(s) + indent <= cols)
    return [" " * indent + line for line in body]


# Approximate Inter advance widths in em (only used to decide line breaks).
_NARROW = set("iljI.,:;!|'()[] ")
_SEMI = set('ftr-"/1')
_WIDE = set("mwMW@%")


def sans_width(text: str, size: float) -> float:
    total = 0.0
    for c in text:
        if c in _NARROW:
            total += 0.29
        elif c in _SEMI:
            total += 0.40
        elif c in _WIDE:
            total += 0.86
        elif c.isupper():
            total += 0.68
        else:
            total += 0.58
    return total * size


def text_el(x: float, y: float, s: str, family: str, size: float, fill: str, **attrs: str) -> str:
    names = {"xml_space": "xml:space"}
    extra = "".join(f' {names.get(k, k.replace("_", "-"))}="{v}"' for k, v in sorted(attrs.items()))
    return (
        f'<text x="{num(x)}" y="{num(y)}" font-family="{family}" font-size="{num(size)}" '
        f'fill="{fill}"{extra}>{escape(s)}</text>'
    )


def terminal_text(scene: dict, t: dict, x: float, y: float, w: float) -> tuple[list[str], float]:
    """The terminal's text lines starting at baseline `y`; returns them and the next baseline."""
    char_w = TERM_FONT * MONO_ADVANCE
    cols = int((w - 2 * TERM_PAD_X) // char_w)
    tx = x + TERM_PAD_X
    ty = y
    out = []
    for style, text in scene["lines"]:
        if style == "cursor":
            out.append(
                f'<rect x="{num(tx)}" y="{num(ty - TERM_FONT + 1)}" width="{num(char_w)}" '
                f'height="{num(TERM_FONT + 3)}" fill="{t["cursor"]}" opacity="0.7"/>'
            )
            ty += TERM_LINE
            continue
        if style == "rule":
            ty += 8
            size = TERM_FONT * 0.82
            label_end = tx + (len(text) + 1) * size * MONO_ADVANCE
            out.append(
                f'<line x1="{num(label_end)}" y1="{num(ty - 4.5)}" x2="{num(x + w - TERM_PAD_X)}" '
                f'y2="{num(ty - 4.5)}" stroke="{t["rule"]}" stroke-dasharray="3 4"/>'
            )
            out.append(text_el(tx, ty, text, MONO, size, t["dim"]))
            ty += TERM_LINE + 6
            continue
        if style == "cmd":
            for j, line in enumerate(wrap_mono(text, cols - 2)):
                if j == 0:
                    out.append(
                        f'<text x="{num(tx)}" y="{num(ty)}" font-family="{MONO}" '
                        f'font-size="{num(TERM_FONT)}" xml:space="preserve">'
                        f'<tspan fill="{t["prompt"]}">$ </tspan>'
                        f'<tspan fill="{t["text"]}">{escape(line)}</tspan></text>'
                    )
                else:
                    out.append(text_el(tx + 2 * char_w, ty, line, MONO, TERM_FONT, t["text"]))
                ty += TERM_LINE
            continue
        color = {"out": t["text"], "dim": t["dim"], "accent": t["accent"]}[style]
        for line in wrap_mono(text, cols):
            out.append(text_el(tx, ty, line, MONO, TERM_FONT, color, xml_space="preserve"))
            ty += TERM_LINE
    return out, ty


def terminal(scene: dict, t: dict) -> list[str]:
    """A terminal window sized to its content, vertically centered."""
    x, w = TERM_X, TERM_W
    first = TERM_BAR + 32
    lines, end = terminal_text(scene, t, x, first, w)
    h = max(end - TERM_LINE + 28, 150)
    y = round((HEIGHT - h) / 2)
    out = [
        f'<rect x="{num(x + 6)}" y="{num(y + 10)}" width="{num(w - 12)}" height="{num(h - 4)}" '
        f'rx="12" fill="#1f2328" opacity="{num(t["shadow"])}" filter="url(#soft)"/>',
        f'<rect x="{num(x + 0.5)}" y="{num(y + 0.5)}" width="{num(w - 1)}" height="{num(h - 1)}" '
        f'rx="11.5" fill="{t["bg"]}" stroke="{t["border"]}"/>',
        f'<path d="M{num(x + 1)} {num(y + TERM_BAR)}V{num(y + 12)}a11 11 0 0 1 11 -11'
        f'H{num(x + w - 12)}a11 11 0 0 1 11 11V{num(y + TERM_BAR)}Z" fill="{t["bar"]}"/>',
        f'<line x1="{num(x + 1)}" y1="{num(y + TERM_BAR + 0.5)}" x2="{num(x + w - 1)}" '
        f'y2="{num(y + TERM_BAR + 0.5)}" stroke="{t["border"]}"/>',
    ]
    for i in range(3):
        cx = x + 20 + i * 18
        out.append(
            f'<circle cx="{num(cx)}" cy="{num(y + TERM_BAR / 2)}" r="5.5" fill="{t["dot"]}"/>'
        )
    out.append(
        text_el(
            x + w / 2,
            y + TERM_BAR / 2 + 4.5,
            scene["title"],
            SANS,
            12,
            t["title"],
            text_anchor="middle",
            font_weight="500",
        )
    )
    out.append(f'<g transform="translate(0 {num(y)})">')
    out += lines
    out.append("</g>")
    return out


# Device geometry (stylized: tall body, screen in the upper part, tapering lower part).
DEV_W = 232.0
DEV_H = 418.0
DEV_X = WIDTH - 40 - DEV_W
DEV_Y = (HEIGHT - DEV_H) / 2
TAPER_Y = 0.60  # where the sides start to slant (fraction of the height)
BOTTOM_W = 0.58  # width at the bottom (fraction of the width)


def device_outline(
    x: float, y: float, w: float, h: float, r: float, taper_y: float, bottom_w: float
) -> str:
    """Rounded top, straight sides, then sides slanting in to a narrower rounded bottom."""
    inset = (w - w * bottom_w) / 2
    ty = y + h * taper_y
    rb = r * 0.75
    # Unit vector along the left slant (downwards).
    dx, dy = inset, y + h - ty
    length = (dx * dx + dy * dy) ** 0.5
    ux, uy = dx / length, dy / length
    k = rb * 0.9  # how far the bottom corner rounding reaches along each edge
    return (
        f"M{num(x)} {num(y + r)}"
        f"Q{num(x)} {num(y)} {num(x + r)} {num(y)}"
        f"H{num(x + w - r)}"
        f"Q{num(x + w)} {num(y)} {num(x + w)} {num(y + r)}"
        f"V{num(ty)}"
        f"L{num(x + w - inset + ux * k)} {num(y + h - uy * k)}"
        f"Q{num(x + w - inset)} {num(y + h)} {num(x + w - inset - k)} {num(y + h)}"
        f"H{num(x + inset + k)}"
        f"Q{num(x + inset)} {num(y + h)} {num(x + inset - ux * k)} {num(y + h - uy * k)}"
        f"L{num(x)} {num(ty)}Z"
    )


def device(scene: dict) -> list[str]:
    title, request, identity = scene["device"]
    x, y, w, h = DEV_X, DEV_Y, DEV_W, DEV_H
    body = device_outline(x, y, w, h, 26, TAPER_Y, BOTTOM_W)

    # Screen: same shape, inset, ending above the lower panel.
    m = 7.0
    sx, sy, sw = x + m, y + m, w - 2 * m
    sh = h * 0.79 - m
    slant_start = (y + h * TAPER_Y - sy) / sh  # same slant start as the body
    # The screen bottom lies on the body's slant, inset by m.
    frac = (sy + sh - (y + h * TAPER_Y)) / (h - h * TAPER_Y)
    screen_bottom_w = (w - (w - w * BOTTOM_W) * frac - 2 * m * 1.1) / sw
    screen = device_outline(sx, sy, sw, sh, 19, slant_start, screen_bottom_w)

    # Lower panel between the screen and the bottom of the body.
    py = sy + sh + 5
    panel_frac = (py - (y + h * TAPER_Y)) / (h - h * TAPER_Y)
    panel_inset = (w - w * BOTTOM_W) / 2 * panel_frac + m
    panel = (
        f"M{num(x + panel_inset)} {num(py)}H{num(x + w - panel_inset)}"
        f"L{num(x + w - (w - w * BOTTOM_W) / 2 - m * 0.9)} {num(y + h - m)}"
        f"H{num(x + (w - w * BOTTOM_W) / 2 + m * 0.9)}Z"
    )

    out = [
        f'<ellipse cx="{num(x + w / 2)}" cy="{num(y + h + 2)}" rx="{num(w * 0.42)}" ry="9" '
        f'fill="#000" opacity="0.28" filter="url(#soft)"/>',
        f'<path d="{body}" fill="url(#body)" stroke="#4b515c" stroke-width="1.2"/>',
        f'<path d="{body}" fill="none" stroke="url(#rim)" stroke-width="2.4" opacity="0.6"/>',
        f'<path d="{panel}" fill="url(#panel)" stroke="#2b3039" stroke-width="0.8" '
        f'stroke-linejoin="round"/>',
        f'<path d="{panel}" fill="url(#gloss)"/>',
        f'<path d="{screen}" fill="#05070c"/>',
        f'<clipPath id="screen-clip"><path d="{screen}"/></clipPath>',
        '<g clip-path="url(#screen-clip)">',
        f'<rect x="{num(sx)}" y="{num(sy)}" width="{num(sw)}" height="{num(sh)}" '
        f'fill="url(#screen)"/>',
    ]

    # Confirm glow band.
    band_y = sy + sh * 0.745
    band_h = sh * 0.19
    out += [
        f'<rect x="{num(sx)}" y="{num(band_y)}" width="{num(sw)}" height="{num(band_h)}" '
        f'fill="url(#glow)"/>',
        f'<rect x="{num(sx + sw * 0.1)}" y="{num(band_y)}" width="{num(sw * 0.8)}" height="1.2" '
        f'fill="url(#glowline)"/>',
        "</g>",
    ]

    pad = 17.0
    tx = sx + pad
    out.append(text_el(tx, sy + 32, title, SANS, 11.5, SCREEN_TITLE, font_weight="500"))
    # Menu icon: three short lines, top right.
    mx = sx + sw - pad - 15
    for i in range(3):
        out.append(
            f'<rect x="{num(mx)}" y="{num(sy + 22.5 + i * 4.5)}" width="15" height="1.6" '
            f'rx="0.8" fill="{SCREEN_TEXT}"/>'
        )

    size = 13.5
    max_w = sw - 2 * pad
    line_y = sy + 62
    for line in wrap_words(request, lambda s: sans_width(s, size) <= max_w):
        out.append(text_el(tx, line_y, line, SANS, size, SCREEN_TEXT, font_weight="600"))
        line_y += size * 1.3
    out.append(text_el(tx, line_y + 22, identity, MONO, 16.5, SCREEN_ID))

    out.append(
        text_el(
            sx + sw / 2,
            band_y + band_h * 0.42 + 5,
            "Confirm",
            SANS,
            14,
            SCREEN_CONFIRM,
            text_anchor="middle",
            font_weight="600",
        )
    )
    return out


def defs() -> str:
    return (
        "<defs>"
        f'<filter id="soft" filterUnits="userSpaceOnUse" x="0" y="0" width="{WIDTH}" '
        f'height="{HEIGHT}"><feGaussianBlur stdDeviation="9"/></filter>'
        '<linearGradient id="body" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#2c313a"/><stop offset="0.55" stop-color="#1b1e24"/>'
        '<stop offset="1" stop-color="#121418"/></linearGradient>'
        '<linearGradient id="rim" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#8a919c"/><stop offset="0.4" stop-color="#3a3f48"/>'
        '<stop offset="1" stop-color="#2a2e35"/></linearGradient>'
        '<linearGradient id="panel" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#22262d"/><stop offset="0.5" stop-color="#14171b"/>'
        '<stop offset="1" stop-color="#0d0f12"/></linearGradient>'
        '<linearGradient id="screen" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#03060f"/><stop offset="0.55" stop-color="#06112a"/>'
        '<stop offset="1" stop-color="#081a3d"/></linearGradient>'
        '<radialGradient id="glow" cx="0.5" cy="0" r="0.85" fx="0.5" fy="0">'
        '<stop offset="0" stop-color="#2d66e6" stop-opacity="0.62"/>'
        '<stop offset="0.5" stop-color="#1a3f9e" stop-opacity="0.24"/>'
        '<stop offset="1" stop-color="#0b1d4a" stop-opacity="0"/></radialGradient>'
        '<linearGradient id="gloss" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#ffffff" stop-opacity="0.09"/>'
        '<stop offset="0.5" stop-color="#ffffff" stop-opacity="0.02"/>'
        '<stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient>'
        '<linearGradient id="glowline" x1="0" y1="0" x2="1" y2="0">'
        '<stop offset="0" stop-color="#5b9bff" stop-opacity="0"/>'
        '<stop offset="0.5" stop-color="#7fb4ff" stop-opacity="0.85"/>'
        '<stop offset="1" stop-color="#5b9bff" stop-opacity="0"/></linearGradient>'
        "</defs>"
    )


def render(scene: dict, theme: str) -> str:
    t = THEMES[theme]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}">',
        defs(),
        *terminal(scene, t),
        *device(scene),
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: render.py <output-dir>")
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for scene in SCENES:
        (out / f"{scene['name']}.svg").write_text(render(scene, "dark"), encoding="utf-8")


if __name__ == "__main__":
    main()
