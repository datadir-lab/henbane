# Henbane — Release Engineering (Foundation + Docker)

- **Status:** Draft for review
- **Date:** 2026-11-14
- **Scope:** Tag-driven release of cross-platform binaries and a multi-arch Docker
  image, with maximal supply-chain assurance. Go install / pkg.go.dev fall out of
  this for free.
- **Deferred (own specs):** Caddy plugin release (blocked: the Caddy module does not
  exist yet), Nix flake / NixOS module, Homebrew tap, release-version automation.

## 1. Goals / Non-goals

### Goals
- One command (`git push` of a semver tag) produces a complete, verifiable release.
- Cross-platform binaries for linux, macOS, Windows, with checksums.
- A multi-arch (`linux/amd64`, `linux/arm64`) Docker image on GHCR.
- Maximal supply chain: syft SBOMs, cosign keyless signatures, and SLSA **L3**
  provenance for both binaries and the image.
- `go install …@latest` and pkg.go.dev work immediately after a tag.
- The pipeline is validated on PRs before any tag is cut.
- Consistent with the repo's hardened CI (SHA-pinned actions, least-privilege, OpenSSF
  Scorecard).

### Non-goals (this spec)
- Publishing to Docker Hub (GHCR only; Docker Hub can be added later).
- A rolling `:edge` image on `main` (decided out of scope; images are released only).
- Automated version bumping / changelog PRs (release-please etc.) — manual tags for now.
- Caddy plugin, middleware, Nix, Homebrew artifacts (deferred).

## 2. Locked decisions
- **Build tooling:** GoReleaser, plus `slsa-framework/slsa-github-generator` reusable
  workflows for L3 provenance.
- **Supply-chain bar:** maximal — cosign (keyless, OIDC/Fulcio/Rekor) + SLSA L3 + syft SBOM.
- **Binary platforms:** linux {amd64, arm64}, darwin {amd64, arm64}, windows {amd64}.
- **Registry:** `ghcr.io/datadir-lab/henbane` only.
- **Trigger:** push of a `v*` semver tag. Pre-1.0 (`v0.x`).

## 3. Trigger & versioning
- A release runs only on pushing a tag matching `v[0-9]+.[0-9]+.[0-9]+` (optionally a
  `-rc.N` / pre-release suffix). Nothing keys on pushes to `main`, so branch protection
  and the required-check gate are untouched.
- Versioning is manual: `git tag v0.1.0 && git push origin v0.1.0`. GoReleaser derives
  the version from the tag. Pre-releases (tags with a hyphen) are marked as GitHub
  pre-releases and excluded from the `latest` Docker tag and the "latest" GitHub release.
- The module path is already `github.com/datadir-lab/henbane`, so semver tags are also
  valid Go module versions.

## 4. Binaries (GoReleaser)
- `.goreleaser.yaml` (schema v2):
  - `builds`: one build, `main: ./cmd/henbane`, `CGO_ENABLED=0`, `flags: -trimpath`,
    `ldflags: -s -w -X main.version={{.Version}} -X main.commit={{.FullCommit}}
    -X main.date={{.CommitDate}}`, `mod_timestamp: {{.CommitTimestamp}}` for reproducible
    builds. `goos: [linux, darwin, windows]`, `goarch: [amd64, arm64]`, with
    `ignore: windows/arm64` (dropped to match the agreed matrix).
  - `archives`: `tar.gz` default, `zip` for windows (`format_overrides`), each including
    `LICENSE`, `README.md`, and the generated SBOM. Name template
    `henbane_{{.Version}}_{{.Os}}_{{.Arch}}`.
  - `checksums`: `checksums.txt`, sha256.
  - `changelog`: grouped from conventional-commit prefixes (feat/fix/perf/…); chores and
    docs filtered or grouped under "Other".
  - `sboms`: syft SPDX JSON per archive (GoReleaser's `sbom` with `anchore/syft`).
  - `signs` / `docker_signs`: cosign keyless (see §6).
  - `release`: GitHub release, `prerelease: auto`, footer linking install + verification docs.

## 5. Docker image
- GoReleaser `dockers` + `docker_manifests` build per-arch images with buildx and assemble
  a multi-arch manifest. Base image: `gcr.io/distroless/static-debian12:nonroot` pinned by
  digest (mirrors the current `Dockerfile` final stage), `USER nonroot`,
  `ENTRYPOINT ["/usr/bin/henbane"]`.
- A slim `Dockerfile.goreleaser` just `COPY`s the prebuilt binary (GoReleaser builds the
  binary, not the image's Go stage). The existing multi-stage `Dockerfile` is kept for
  local `docker build` and documented as such.
- Tags on a release: `vX.Y.Z`, `X.Y`, `X`, and `latest` (latest only for non-pre-release).
- OCI labels: `org.opencontainers.image.source`, `.revision`, `.version`, `.licenses=AGPL-3.0`,
  `.title=henbane`, `.description` (the repo tagline).
- GHCR auth in CI via `GITHUB_TOKEN` with `packages: write`; image made public on first push.

## 6. Supply chain (maximal)
Three layers, binaries and image each:

1. **SBOM (syft, SPDX JSON).** Per-archive SBOMs via GoReleaser's `sbom`; an image SBOM
   generated against the pushed digest. SBOMs are uploaded as release assets and attested.
2. **Signatures (cosign, keyless).** cosign via Sigstore OIDC (Fulcio cert + Rekor
   transparency log), no long-lived keys. Signs `checksums.txt` (covering every binary) and
   each image by digest. Verification uses the workflow identity (issuer =
   `https://token.actions.githubusercontent.com`, identity = this repo's release workflow).
3. **SLSA L3 provenance (`slsa-github-generator`).** Generated in the project's *trusted
   reusable workflows* so the build cannot forge its own provenance (the L3 requirement):
   - Binaries: `generator_generic_slsa3.yml` consumes the base64 sha256 hashes GoReleaser
     emits for all artifacts and produces one provenance attestation attached to the release.
   - Image: `generator_container_slsa3.yml` consumes `{image, digest}` and produces provenance
     pushed to GHCR alongside the image.

Everything is reproducible-friendly (`-trimpath`, `mod_timestamp`, pinned base digest).

## 7. Go module reference
- No code needed for installability: once a `v*` tag exists,
  `go install github.com/datadir-lab/henbane/cmd/henbane@latest` resolves it and pkg.go.dev
  auto-indexes.
- The release workflow warms the proxy (`GOPROXY=proxy.golang.org go list -m
  github.com/datadir-lab/henbane@<tag>`) so the version and docs appear on pkg.go.dev without
  waiting for an organic request.
- README gains an **Install** section (go install / docker pull / download+verify) and a
  **Verifying releases** section (cosign verify-blob, `slsa-verifier`, `gh attestation verify`,
  and `cosign verify` for the image).

## 8. Version injection & `--version`
- Add `cmd/henbane`: package-level `var version, commit, date = "dev", "none", "unknown"`
  (overridden by ldflags) and a `--version` flag that prints `henbane <version>
  (<commit>, <date>)` and exits 0.
- On startup the existing structured log line gains a `version` field.
- `--version` must work before the `--upstream` requirement is enforced (parse it first).
- Unit test: `--version` prints and exits 0 without requiring `--upstream`.

## 9. CI integration & testing the pipeline
- **Config lint:** a `goreleaser check` step (and `--snapshot` dry run) added to `ci.yml`,
  triggered when release files change, so a broken `.goreleaser.yaml` fails PR CI.
- **Dry run:** `goreleaser release --snapshot --clean` builds every target and the image
  locally and publishes nothing — the main guard against release-day breakage.
- **First real cut:** tag `v0.1.0` to exercise the full path end-to-end; then verify the
  published signatures, SBOMs, and L3 provenance from a clean machine before announcing.
- **Acceptance criteria:** a tagged release yields, for every target, a signed archive +
  SBOM + L3 provenance; a signed multi-arch image with provenance; a GitHub release with
  `checksums.txt`; `go install …@<tag>` succeeds; all three verification commands pass.

## 10. Permissions & security
- Each job requests only what it needs:
  - GoReleaser job: `contents: write` (release assets), `packages: write` (GHCR),
    `id-token: write` (cosign OIDC).
  - SLSA generator jobs: as required by the reusable workflows (`id-token: write`,
    `contents: write`, `actions: read`).
- All third-party actions pinned by commit SHA (repo convention); the SLSA reusable
  workflows pinned to a release tag as their docs require.
- Default `GITHUB_TOKEN` permissions stay read-only at the workflow level; write scopes are
  granted per-job. Scorecard's token-permissions check must still pass.

## 11. Files added / changed
- **New:** `.goreleaser.yaml`, `.github/workflows/release.yml`, `Dockerfile.goreleaser`.
- **Changed:** `cmd/henbane` (`version`/`commit`/`date` vars + `--version`), `README.md`
  (Install + Verifying releases), `.github/workflows/ci.yml` (goreleaser check + snapshot job),
  `.dockerignore` if needed for the release Dockerfile context.

## 12. Deferred / future work
- **Caddy plugin release** — once the Caddy module (design slice 10) exists: `xcaddy` build
  matrix, a `caddy`-with-henbane image, and provenance for both. Separate spec.
- **Nix** — a flake exposing the package + a NixOS systemd module; can consume release
  binaries or build from source. Separate spec.
- **Homebrew tap** and **release automation** (release-please) — easy GoReleaser add-ons later.
- **Docker Hub** mirror — optional second registry.

## 13. Risks & mitigations
- *GoReleaser is a large dependency in the release path.* → Pin by SHA, keep the config
  auditable, and the SLSA provenance + cosign signatures make any tampering detectable.
- *SLSA L3 + GoReleaser wiring is fiddly (hashes hand-off).* → Follow GoReleaser's documented
  SLSA pattern; the `--snapshot` dry run plus the `v0.1.0` smoke release catch mistakes before
  they matter.
- *Keyless cosign depends on Sigstore availability.* → Acceptable; failures fail the release
  loudly rather than publishing unsigned artifacts.
- *First GHCR push visibility / permissions.* → Document making the package public and the
  one-time org settings; verify in the `v0.1.0` cut.
