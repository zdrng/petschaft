# petschaft logo

**Logo: variant B "Signet p".** Variant A is an alternative design.

## Variants

Two original designs on a black background. Both use the same palette: black `#000000`,
white `#FFFFFF`, greys `#93969A` `#6A6B6D`, and one small accent, the "Confirm" cyan `#62E6DC` of the device screens in the README images (`docs/img/render.py`).
In both variants the cyan marks the same thing: the moment the device seals a signature.
Overview: `comparison.png` (large squircles plus 120 px and 60 px versions).

| Variant | Name | Concept |
|---|---|---|
| A | Sealed commit | A commit history: a grey line through two older commits (dark grey, lighter grey) to the newest commit, a white node in a cyan ring. Commits form a hash chain, so the one signature on the newest commit seals the whole history before it. |
| B | Signet p | A geometric lowercase "p": a white stem and a ring for the bowl. The bowl is the face of a signet (German *Petschaft*) seen from above; the cyan dot in it is the imprint, the single press on the device that seals. |

Why B: it is the more distinctive mark (a letter like a wordmark, bold at 60 px) and does not
resemble any vendor's device. Its meaning sits in the shape: the bowl is the signet face,
the cyan dot the imprint, the one press on the device that seals. A is the more literal git
mark but says nothing about SSH or APKs.

## Files

| File | Purpose |
|---|---|
| `variant-x.svg` | Full icon, 1024×1024, full-bleed black square, no rounded corners (a mask is applied where it is shown). |
| `variant-x.png` | 1024×1024 render of the above (resvg). |
| `comparison.png` | Comparison sheet: large squircle previews plus 120 px and 60 px versions. |
| `readme-icon.png` | The chosen variant in a squircle, 240×240, shown at 120 px at the top of the main README. |
| `build.py` | Generates the SVGs above (Python stdlib only, deterministic); the flake renders the PNGs. |

## Switch to another variant

Set `DEFAULT = "a"` (or `"b"`) at the top of `build.py` and regenerate. That rewrites
`readme-icon.png` and moves the "chosen" label in `comparison.png`. Update the first line
of this README and the `alt` text of the image in the main README.

## Regenerate

From the repository root (`build.py` must be `git add`-ed, otherwise Nix does not see it):

```sh
nix build .#readme-logos -o result-logo
install -m 644 result-logo/* docs/img/logo/ && rm result-logo
```

The sheet labels use Inter from nixpkgs; resvg runs with `--skip-system-fonts`, so the output
does not depend on the fonts of the machine.
