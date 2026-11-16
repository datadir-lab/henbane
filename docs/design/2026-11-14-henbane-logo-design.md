# Henbane: Logo Design Brief

- **Status:** Approved brief (ready to execute)
- **Date:** 2026-11-14
- **Project dir:** `D:\dev\hacktivism\poison\henbane`
- **Scope:** Visual identity (logo) for the `henbane` project: standalone, not the
  broader Poison Garden family system.

---

## 1. Concept & mood

An **antique herbal-engraving specimen** of henbane (*Hyoscyamus niger*): beautiful but
faintly sinister. It reads as *apothecary / poison garden*: a poison plant drawn with the
care of a 17th-century botanical plate, standing guard. The mark signals the project's
nature without a word: henbane is a gateway that poisons abusive scrapers, and the logo
is, fittingly, a poison plant.

**Adjectives:** botanical, engraved, apothecary, restrained, a little sinister, crafted.

## 2. Decisions (locked)

| Dimension | Decision | Notes |
|---|---|---|
| **Direction** | Botanical mark | Not symbolic/typographic-only; the plant is the identity. |
| **Style** | Herbal woodcut / engraving | Fine linework + hatching; antique botanical plate. |
| **Subject** | Flower sprig | One veined bell/funnel flower (dark throat) **+** the row of seed-pod capsules (pyxides) on a single stem. Beauty (bloom) + menace (pods). |
| **Palette** | Monochrome ink, `currentColor` | One ink color; the file themes itself to any light/dark context. No baked-in colors. |
| **Family** | Standalone | Optimize purely for henbane; no constraints from hypothetical siblings (Belladonna, Mandrake, Hemlock). |
| **Wordmark** | Classic old-style serif, lowercase | `henbane` lowercase; italic Latin binomial *Hyoscyamus niger* as a small caption. Apothecary-plate cohesion. |

## 3. The mark (hero)

- **Subject:** a focused flower sprig: a single bell/funnel bloom with visible
  net-veining and a dark throat, above the characteristic row of urn-shaped seed-pod
  capsules on one upright stem. A couple of leaves for silhouette, kept minimal.
- **Rendering:** monochrome **ink engraving**: contour linework plus engraving hatching
  for shading (parallel/cross-hatch in the throat and pod shadows). Disciplined detail:
  enough to feel like a real plate, not so much it muddies.
- **Color:** single color via `currentColor`. No gradients, no multiple fills.
- **Format:** SVG, roughly square-ish `viewBox`, strokes/paths authored so the whole mark
  reads cleanly on light and dark grounds.

## 4. Simplified glyph (favicon / CLI / 16px)

A reduced, one-color derivative of the hero that survives small sizes and the one-color
test:
- Keep the bell flower + one pod (the recognizable silhouette DNA of the hero).
- Drop fine hatching; thicken strokes; simplify veins to 2-3 strokes.
- Verified legible at **16px** and as a solid one-color shape.
- Ships as `currentColor` SVG; PNG favicon sizes (16/32/180/512) generated from it with
  sizing guidance.

## 5. Wordmark & lockups

- **Wordmark:** `henbane`, lowercase, in a transitional/old-style serif (letterpress
  herbal feel). Delivered as **outlined paths** (or a safe, documented font stack) so it
  renders identically everywhere.
- **Caption (optional element):** *Hyoscyamus niger* in italic, small, for plate-style
  lockups.
- **Primary lockup:** glyph left + wordmark right.
- **Secondary lockup:** stacked (glyph over wordmark) for square/avatar/social use.

## 6. Deliverables

- `henbane-hero.svg`: detailed engraving mark (`currentColor`).
- `henbane-glyph.svg`: simplified favicon/app glyph (`currentColor`).
- `henbane-lockup.svg`: horizontal glyph + wordmark; plus a stacked variant.
- Favicon set + sizing guidance (16/32/180/512 PNG from the glyph).
- An HTML **preview page** showing every asset at real sizes, in light and dark.
- *(optional)* `henbane.ascii`: a terminal/CLI startup banner (sprig + wordmark) for the
  `henbane` CLI.

Proposed home in the repo: `assets/logo/` (or `brand/`), decided at execution time.

## 7. Technical constraints (from `making-svg-logos`)

- Single color via `currentColor`; no hard-coded palette in the shipping marks.
- Clean, minimal `viewBox`; no stray transforms or editor cruft.
- Wordmark text converted to outlines (or an explicit, safe fallback stack).
- **Must pass the 16px test and the one-color test**: the glyph is tuned specifically
  for this; the hero degrades gracefully to the glyph when too small.
- Optical correction over mathematical centering where they disagree.

## 8. Open / deferred

- Exact repo location for assets (`assets/logo/` vs `brand/`): decide at execution.
- Whether to ship the ASCII banner now or defer: optional.
- Natural-color "poison palette" plate (sulphur petals / oxblood veins) is explicitly
  **out of scope** for v1; monochrome is the system. Could be a future hero-image variant.

## 9. Next step

Execute with the `making-svg-logos` skill: draft the hero engraving, derive the glyph,
build the lockups, and render the preview page, then iterate on the visual candidates.
