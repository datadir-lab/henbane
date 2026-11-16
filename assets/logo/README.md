# Henbane: brand & logo

The henbane mark is a single bloom of *Hyoscyamus niger* **segmented out of a real
photograph** (OpenCV GrabCut) and rendered in the flower's own palette: pale straw-yellow
petals, a purple net of veins, and a near-black throat. It is not a drawn icon; the detail
is the point.

## The marks

| File | Use |
|---|---|
| `henbane-flower.png` | **Primary.** Flower only, transparent, cut out clean. Sits on any ground. 1024², RGBA. |
| `henbane-flower-dark.png` | Reverse / dark grounds (veins kept light so they read on black). 1024², RGBA. |
| `henbane-flower-128.png` | Small size (headers, avatars, ≥32 px). |
| `henbane-logo-green*.png` | **Alternate.** The same bloom inside a square keyline with a faint background. Kept for reference; not the primary. |

> **Favicon note.** Any photo-derived bloom turns to mush at 16 px. The flower reads well
> from ~32 px up. A crisp 16/32 favicon needs a **separate simplified glyph** (a bold
> 3-5-lobe silhouette drawn from this flower), not yet produced.

## Colour

The **mark** carries the flower's own henbane palette (straw-yellow, purple, dark throat).
The **UI** stays monochrome green over two grounds, so the flower is the one richly-colored
element. Accent greens are additive; meaning never depends on hue. All text pairs below pass
**WCAG AA** (≥4.5:1 normal, ≥3:1 large/UI), audited, see ratios.

| Role | Hex | On | Ratio |
|---|---|---|---|
| Parchment ground | `#f0eedd` | n/a | n/a |
| Night ground | `#14140f` | n/a | n/a |
| Ink (text on light) | `#1b1d14` | parchment | 14.6 |
| Bone (text on dark) | `#e8ecd8` | night | 15.3 |
| Muted on light | `#524f43` | parchment | 5.4 |
| Muted on dark | `#929a79` | night | 6.3 |
| Fine print on dark | `#868d6e` | night | 5.3 |
| Deep-green accent | `#33512f` | parchment | 7.6 |
| Lime accent | `#8fae63` | night | 6.7 |

Flower tones (imagery, not text): straw-yellow petals `~#c6c078→#e0db96`, purple net-veins
`~#604678→#7c5e8f`, near-black throat `~#241434`, darkest at the center.

## Type

- **Wordmark / display:** UnifrakturMaguntia (blackletter). Pirata One as a display alt.
- **Text / captions:** IM Fell English (roman + italic).
- **Mono:** system `ui-monospace`.

All three families are **SIL Open Font License**, embedded base64 in `fonts.css` (self-contained,
dodges Chrome's `file://` font-CORS). Sources in `fonts/`.

## Pages

| File | What |
|---|---|
| `logos.html` | Brand sheet: the mark, usage, light + dark + sizes. |
| `logo-screens.html` | The mark in use: browser tab, app/avatar icons, GitHub header, social card, CLI, favicon sizes. |
| `challenge.html` | Proposed proof-of-work interstitial (the themeable challenge page), explaining the wait and why AI scrapers cause it. |
| `favicon-test.html` | Flower-only vs. bordered, 128→16 px, light + dark. |
| `shader.html` | **The forge.** A self-contained WebGL playground that drives source imagery through threshold / halftone / dither / engraving / duotone, with crop, frame, palette and PNG export. Images baked into `src/images.js`. |

## Provenance & licensing

- Source photograph: *Hyoscyamus niger*, **public domain**, Wikimedia Commons (Category:Hyoscyamus niger).
  Working crop: `src/crop3/ph42.jpg`. Hand-adjusted cut-out outline: `src/ph42-mask-draw.png`.
  Final segmentation mask: `variations/fg-mask.png`.
- Fonts: OFL (see above).

## Regenerating the mark

The flower is produced by a Python + OpenCV pipeline (not the forge, which can't segment):
`src/crop3/ph42.jpg` → GrabCut (green + smooth-background seeds) → clean mask
(`variations/fg-mask.png`) → two-green duotone within the mask + radial throat gradient →
transparent RGBA, tight-cropped and centred. The forge (`shader.html`) is for exploring other
treatments/sources.
