# Release Foundation + Docker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `git push` of a semver tag produces cross-platform binaries and a multi-arch GHCR image, each with syft SBOMs, cosign keyless signatures, and SLSA L3 provenance; `go install …@latest` and pkg.go.dev work immediately.

**Architecture:** GoReleaser builds binaries, archives, checksums, SBOMs, the multi-arch image, and the GitHub release, and cosign-signs the checksums and image. A `release.yml` workflow runs GoReleaser on a `v*` tag, then calls the trusted `slsa-github-generator` reusable workflows to attach SLSA L3 provenance to the binaries (generic generator over the checksum hashes) and the image (container generator over the pushed digest). CI gains a non-publishing GoReleaser dry run so release breakage is caught on PRs.

**Tech Stack:** Go 1.26, GoReleaser v2, cosign (keyless/Sigstore), syft (SBOM), slsa-github-generator reusable workflows, Docker buildx, GitHub Actions.

**Spec:** `docs/design/2026-11-14-release-engineering.md`

## Global Constraints

Every task's requirements implicitly include these:

- Module path `github.com/datadir-lab/henbane`; Go `1.26.11`.
- Binary targets: linux {amd64, arm64}, darwin {amd64, arm64}, windows {amd64} (no windows/arm64).
- Build flags: `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w"`, reproducible via `mod_timestamp`.
- Registry: `ghcr.io/datadir-lab/henbane` only. Image base: `gcr.io/distroless/static-debian12:nonroot` (pinned by digest), `USER nonroot`.
- Supply chain: syft SPDX SBOM, cosign keyless (OIDC/Fulcio/Rekor), SLSA **L3** via `slsa-framework/slsa-github-generator`.
- Trigger: push of a `v[0-9]+.[0-9]+.[0-9]+` tag (optional `-rc.N`). Pre-1.0. `latest` Docker tag only for non-pre-releases.
- All third-party actions pinned by commit SHA (reuse existing pins where available); SLSA reusable workflows referenced by their release tag per SLSA docs.
- Conventional commits (enforced by `conform`). **No `Co-Authored-By` trailers. No em-dashes in docs copy.**
- OCI label `org.opencontainers.image.licenses=AGPL-3.0`.
- Known-good action pins to reuse: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`, `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0`.

---

### Task 1: Version metadata and `--version` flag

**Files:**
- Create: `cmd/henbane/version.go`
- Create: `cmd/henbane/version_test.go`
- Modify: `cmd/henbane/main.go` (intercept `--version` before `config.Parse`; add `version` to the startup log in `serve`)

**Interfaces:**
- Produces: `var version, commit, date string` (package `main`, ldflag targets `main.version`/`main.commit`/`main.date`); `versionString() string`; `maybePrintVersion(args []string, w io.Writer) bool`.

- [ ] **Step 1: Write the failing test**

Create `cmd/henbane/version_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestVersionStringIncludesAllFields(t *testing.T) {
	version, commit, date = "1.2.3", "abc1234", "2026-11-14"
	got := versionString()
	for _, want := range []string{"henbane", "1.2.3", "abc1234", "2026-11-14"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionString()=%q, missing %q", got, want)
		}
	}
}

func TestMaybePrintVersionPrintsAndReports(t *testing.T) {
	version = "9.9.9"
	var buf strings.Builder
	if !maybePrintVersion([]string{"--version"}, &buf) {
		t.Fatal("maybePrintVersion(--version) = false, want true")
	}
	if !strings.Contains(buf.String(), "9.9.9") {
		t.Errorf("output %q does not contain version", buf.String())
	}
}

func TestMaybePrintVersionIgnoresOtherArgs(t *testing.T) {
	var buf strings.Builder
	if maybePrintVersion([]string{"--upstream", "http://x"}, &buf) {
		t.Fatal("maybePrintVersion(--upstream) = true, want false")
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected output %q", buf.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/henbane/ -run 'Version|MaybePrintVersion' -v`
Expected: FAIL (compile error: `versionString`/`maybePrintVersion` undefined).

- [ ] **Step 3: Write minimal implementation**

Create `cmd/henbane/version.go`:

```go
package main

import (
	"fmt"
	"io"
)

// Build metadata, overridden at release time via -ldflags
// (-X main.version=... -X main.commit=... -X main.date=...).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString is the one-line human-readable build identity.
func versionString() string {
	return fmt.Sprintf("henbane %s (%s, %s)", version, commit, date)
}

// maybePrintVersion prints the version to w and returns true if any arg
// requests it. Checked before config parsing so --version never requires
// --upstream.
func maybePrintVersion(args []string, w io.Writer) bool {
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Fprintln(w, versionString())
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Wire into `main` and the startup log**

In `cmd/henbane/main.go`, make the first statements of `main()`:

```go
func main() {
	if maybePrintVersion(os.Args[1:], os.Stdout) {
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// ...existing body unchanged...
```

In `serve`, add the version to the existing startup log line:

```go
	logger.Info("henbane starting", "version", version, "listen", cfg.Listen, "upstream", cfg.Upstream)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cmd/henbane/ -v`
Expected: PASS (new tests plus existing `app_test.go` tests).

- [ ] **Step 6: Manual smoke check**

Run: `go run -ldflags "-X main.version=0.0.0-test" ./cmd/henbane --version`
Expected: prints `henbane 0.0.0-test (none, unknown)` and exits 0 with no `--upstream` error.

- [ ] **Step 7: Commit**

```bash
git add cmd/henbane/version.go cmd/henbane/version_test.go cmd/henbane/main.go
git commit -m "feat(cmd): add version metadata and --version flag"
```

---

### Task 2: GoReleaser config and release Dockerfile

**Files:**
- Create: `.goreleaser.yaml`
- Create: `Dockerfile.goreleaser`

**Interfaces:**
- Produces: `dist/checksums.txt` (sha256 of all archives); multi-arch image `ghcr.io/datadir-lab/henbane:{version}` and `:latest`; SBOMs `*.sbom.json`; cosign `.sig`/`.pem` for checksums; the `.goreleaser.yaml` config that Task 3's workflow invokes.

- [ ] **Step 1: Create the release Dockerfile**

Create `Dockerfile.goreleaser` (consumes the prebuilt binary GoReleaser copies into the build context; mirrors the existing `Dockerfile` final stage):

```dockerfile
# syntax=docker/dockerfile:1
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY henbane /usr/bin/henbane
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/henbane"]
```

(If the digest above drifts, copy the current one from the existing `Dockerfile` final stage.)

- [ ] **Step 2: Create `.goreleaser.yaml`**

```yaml
version: 2

project_name: henbane

before:
  hooks:
    - go mod download

builds:
  - id: henbane
    main: ./cmd/henbane
    binary: henbane
    env:
      - CGO_ENABLED=0
    flags:
      - -trimpath
    ldflags:
      - -s -w
      - -X main.version={{ .Version }}
      - -X main.commit={{ .FullCommit }}
      - -X main.date={{ .CommitDate }}
    mod_timestamp: "{{ .CommitTimestamp }}"
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ignore:
      - goos: windows
        goarch: arm64

archives:
  - id: henbane
    ids: [henbane]
    name_template: "henbane_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    formats: [tar.gz]
    format_overrides:
      - goos: windows
        formats: [zip]
    files:
      - LICENSE
      - README.md

checksum:
  name_template: checksums.txt
  algorithm: sha256

sboms:
  - id: archive
    artifacts: archive

signs:
  - id: checksum-keyless
    cmd: cosign
    signature: "${artifact}.sig"
    certificate: "${artifact}.pem"
    args:
      - sign-blob
      - "--output-signature=${signature}"
      - "--output-certificate=${certificate}"
      - "--yes"
      - "${artifact}"
    artifacts: checksum
    output: true

dockers:
  - id: amd64
    goos: linux
    goarch: amd64
    dockerfile: Dockerfile.goreleaser
    use: buildx
    image_templates:
      - "ghcr.io/datadir-lab/henbane:{{ .Version }}-amd64"
    build_flag_templates:
      - "--platform=linux/amd64"
      - "--label=org.opencontainers.image.title=henbane"
      - "--label=org.opencontainers.image.source=https://github.com/datadir-lab/henbane"
      - "--label=org.opencontainers.image.version={{ .Version }}"
      - "--label=org.opencontainers.image.revision={{ .FullCommit }}"
      - "--label=org.opencontainers.image.licenses=AGPL-3.0"
  - id: arm64
    goos: linux
    goarch: arm64
    dockerfile: Dockerfile.goreleaser
    use: buildx
    image_templates:
      - "ghcr.io/datadir-lab/henbane:{{ .Version }}-arm64"
    build_flag_templates:
      - "--platform=linux/arm64"
      - "--label=org.opencontainers.image.title=henbane"
      - "--label=org.opencontainers.image.source=https://github.com/datadir-lab/henbane"
      - "--label=org.opencontainers.image.version={{ .Version }}"
      - "--label=org.opencontainers.image.revision={{ .FullCommit }}"
      - "--label=org.opencontainers.image.licenses=AGPL-3.0"

docker_manifests:
  - name_template: "ghcr.io/datadir-lab/henbane:{{ .Version }}"
    image_templates:
      - "ghcr.io/datadir-lab/henbane:{{ .Version }}-amd64"
      - "ghcr.io/datadir-lab/henbane:{{ .Version }}-arm64"
  - name_template: "ghcr.io/datadir-lab/henbane:latest"
    skip_push: auto
    image_templates:
      - "ghcr.io/datadir-lab/henbane:{{ .Version }}-amd64"
      - "ghcr.io/datadir-lab/henbane:{{ .Version }}-arm64"

docker_signs:
  - id: image-keyless
    cmd: cosign
    artifacts: manifests
    args: ["sign", "--yes", "${artifact}@${digest}"]
    output: true

changelog:
  use: github
  sort: asc
  groups:
    - title: Features
      regexp: '^feat'
      order: 0
    - title: Fixes
      regexp: '^(fix|perf)'
      order: 1
    - title: Other
      order: 99
  filters:
    exclude:
      - "^Merge "

release:
  prerelease: auto
  footer: |
    Verify this release: see "Verifying releases" in the README.
```

- [ ] **Step 3: Lint the config**

Run: `goreleaser check`
Expected: `config is valid`. If a key name is rejected (GoReleaser v2 syntax drift, e.g. `formats` vs `format`), adjust to what `check` reports, then re-run until valid.

- [ ] **Step 4: Full dry run (build everything, publish nothing)**

Run: `goreleaser release --snapshot --clean --skip=sign,docker,sbom`
Expected: `dist/` fills with archives for all five targets plus `checksums.txt`; exit 0.

Note: `--skip=sign,docker,sbom` avoids needing cosign/buildx/syft locally; the full chain is exercised in CI (Task 3) and the smoke release (Task 6).

- [ ] **Step 5: Commit**

```bash
git add .goreleaser.yaml Dockerfile.goreleaser
git commit -m "build: add goreleaser config and release dockerfile"
```

---

### Task 3: Release workflow with SLSA L3 provenance

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `.goreleaser.yaml`, `Dockerfile.goreleaser` (Task 2); `version` ldflags (Task 1).
- Produces: on a `v*` tag, a published GitHub release with signed archives + SBOMs + L3 provenance, and a signed multi-arch GHCR image with L3 provenance.

- [ ] **Step 1: Create the workflow**

Create `.github/workflows/release.yml`:

```yaml
name: release

on:
  push:
    tags: ["v*"]

permissions: {}

jobs:
  goreleaser:
    runs-on: ubuntu-latest
    permissions:
      contents: write     # create the GitHub release
      packages: write      # push to GHCR
      id-token: write      # cosign keyless OIDC
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
      image: ${{ steps.image.outputs.name }}
      digest: ${{ steps.image.outputs.digest }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - uses: docker/setup-qemu-action@v3            # TODO pin to SHA before merge
      - uses: docker/setup-buildx-action@v3          # TODO pin to SHA before merge
      - uses: docker/login-action@v3                 # TODO pin to SHA before merge
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: sigstore/cosign-installer@v3           # TODO pin to SHA before merge
      - uses: anchore/sbom-action/download-syft@v0   # TODO pin to SHA before merge
      - uses: goreleaser/goreleaser-action@v6        # TODO pin to SHA before merge
        with:
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Compute binary hashes for provenance
        id: hash
        run: echo "hashes=$(base64 -w0 dist/checksums.txt)" >> "$GITHUB_OUTPUT"
      - name: Resolve pushed image digest
        id: image
        run: |
          name="ghcr.io/datadir-lab/henbane"
          digest="$(docker buildx imagetools inspect "${name}:${GITHUB_REF_NAME#v}" --format '{{json .Manifest.Digest}}' | tr -d '"')"
          echo "name=${name}" >> "$GITHUB_OUTPUT"
          echo "digest=${digest}" >> "$GITHUB_OUTPUT"
      - name: Warm the Go module proxy
        run: |
          curl -fsS "https://proxy.golang.org/github.com/datadir-lab/henbane/@v/${GITHUB_REF_NAME}.info" || true

  provenance-binaries:
    needs: goreleaser
    permissions:
      id-token: write
      contents: write
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0 # confirm current tag
    with:
      base64-subjects: ${{ needs.goreleaser.outputs.hashes }}
      upload-assets: true

  provenance-image:
    needs: goreleaser
    permissions:
      id-token: write
      packages: write
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0 # confirm current tag
    with:
      image: ${{ needs.goreleaser.outputs.image }}
      digest: ${{ needs.goreleaser.outputs.digest }}
      registry-username: ${{ github.actor }}
    secrets:
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: Pin the new actions to commit SHAs**

For each `# TODO pin to SHA` action, resolve its release tag to a commit SHA and replace `@vN` with `@<sha> # vN`. Confirm the current `slsa-github-generator` release tag (the generator must be referenced by a release tag, not a SHA) and update both `@v2.1.0` references.

Run (example): `gh api repos/goreleaser/goreleaser-action/git/refs/tags/v6 --jq '.object.sha'`
Expected: a 40-char SHA to pin with.

- [ ] **Step 3: Lint the workflow**

Run: `actionlint .github/workflows/release.yml` (if available) or `gh workflow view release.yml` after push.
Expected: no syntax errors.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow with goreleaser and slsa l3 provenance"
```

---

### Task 4: CI dry-run guard for the release config

**Files:**
- Modify: `.github/workflows/ci.yml` (add a `release-dryrun` job)

**Interfaces:**
- Consumes: `.goreleaser.yaml` (Task 2).
- Produces: a required-on-PR check that fails if the release config or build breaks.

- [ ] **Step 1: Add the job**

Append to the `jobs:` map in `.github/workflows/ci.yml`:

```yaml
  release-dryrun:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - uses: goreleaser/goreleaser-action@v6 # TODO pin to SHA before merge (reuse Task 3 pin)
        with:
          version: "~> v2"
          args: check
      - uses: goreleaser/goreleaser-action@v6 # TODO pin to SHA before merge (reuse Task 3 pin)
        with:
          version: "~> v2"
          args: release --snapshot --clean --skip=sign,docker,sbom
```

- [ ] **Step 2: Verify locally that both commands succeed**

Run: `goreleaser check && goreleaser release --snapshot --clean --skip=sign,docker,sbom`
Expected: `config is valid` then a successful snapshot build (exit 0).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: dry-run goreleaser config and build on pull requests"
```

Note: after this merges, add `release-dryrun` to the branch protection required checks for `main` (one-time repo setting; call out in the PR).

---

### Task 5: README install and verification docs

**Files:**
- Modify: `README.md` (add "Install" and "Verifying releases" sections before "Design and brand")

**Interfaces:**
- Consumes: the artifact names and tags produced by Tasks 2 and 3.

- [ ] **Step 1: Add the Install section**

Insert after the "Quick start" section:

```markdown
## Install

**Go:**

```bash
go install github.com/datadir-lab/henbane/cmd/henbane@latest
```

**Docker:**

```bash
docker pull ghcr.io/datadir-lab/henbane:latest
docker run -p 8080:8080 ghcr.io/datadir-lab/henbane --upstream http://host.docker.internal:3000
```

**Binaries:** download the archive for your platform from the
[latest release](https://github.com/datadir-lab/henbane/releases/latest), then verify it (below).
```

- [ ] **Step 2: Add the Verifying releases section**

Insert just before "## Design and brand":

```markdown
## Verifying releases

Every release ships a syft SBOM, a cosign keyless signature, and SLSA L3 provenance.

Verify the checksums signature (binaries):

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/datadir-lab/henbane/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Verify binary provenance (SLSA):

```bash
slsa-verifier verify-artifact henbane_<ver>_<os>_<arch>.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/datadir-lab/henbane
```

Verify the image signature and provenance:

```bash
cosign verify ghcr.io/datadir-lab/henbane:<ver> \
  --certificate-identity-regexp '^https://github.com/datadir-lab/henbane/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

slsa-verifier verify-image ghcr.io/datadir-lab/henbane:<ver> \
  --source-uri github.com/datadir-lab/henbane
```
```

- [ ] **Step 3: Check copy for banned patterns**

Run: `grep -c "—" README.md` (expected `0`) and re-read the new sections for any `Co-Authored-By` or em-dash.
Expected: 0 em-dashes.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add install and release-verification sections"
```

---

### Task 6: Smoke release and end-to-end verification

**Note:** This task has real side effects (publishes a GitHub release and a public GHCR image). Do it only after Tasks 1 to 5 are merged to `main` and CI is green.

**Files:** none (operational).

- [ ] **Step 1: Tag and push**

```bash
git switch main && git pull
git tag v0.1.0
git push origin v0.1.0
```

- [ ] **Step 2: Watch the release workflow**

Run: `gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')`
Expected: `goreleaser`, `provenance-binaries`, and `provenance-image` jobs all succeed.

- [ ] **Step 3: Verify the published artifacts**

Run the four verification commands from Task 5 against the real `v0.1.0` assets and the `ghcr.io/datadir-lab/henbane:0.1.0` image.
Expected: each prints a successful verification.

- [ ] **Step 4: Verify the module is installable and indexed**

Run: `go install github.com/datadir-lab/henbane/cmd/henbane@v0.1.0 && henbane --version`
Expected: prints `henbane 0.1.0 (...)`. Then confirm `https://pkg.go.dev/github.com/datadir-lab/henbane` shows `v0.1.0`.

- [ ] **Step 5: Make the GHCR package public (one-time)**

In GHCR package settings for `henbane`, set visibility to public. Re-run `docker pull ghcr.io/datadir-lab/henbane:0.1.0` unauthenticated to confirm.

---

## Self-Review

**Spec coverage:**
- Trigger & versioning (spec §3) → Task 3 (`on: push: tags`), Task 6.
- Binaries / GoReleaser (§4) → Task 2.
- Docker image (§5) → Task 2 (`dockers`/`docker_manifests`, `Dockerfile.goreleaser`).
- Supply chain: SBOM/cosign/SLSA L3 (§6) → Task 2 (sbom, signs, docker_signs) + Task 3 (SLSA generators).
- Go reference (§7) → Task 3 (proxy warm) + Task 5 (install docs) + Task 6 (verify).
- Version + `--version` (§8) → Task 1.
- CI dry run (§9) → Task 4; smoke release → Task 6.
- Permissions (§10) → Task 3 per-job permissions.
- Files (§11) → all tasks; `README` verify docs → Task 5.

**Placeholder scan:** The `# TODO pin to SHA` markers are deliberate, explicit, actionable steps (Task 3 Step 2, Task 4 note), not vague placeholders. No other TODOs.

**Type consistency:** `version`/`commit`/`date` vars and `versionString`/`maybePrintVersion` are defined in Task 1 and only referenced there and via ldflags; artifact names (`checksums.txt`, `henbane_<ver>_<os>_<arch>`) are consistent across Tasks 2, 3, 5, 6.

**Known risk carried from the spec:** the GoReleaser v2 config keys (`formats`, `sboms`, `skip_push: auto`) and the image-digest resolution step may need small syntax tweaks; Task 2 Step 3 (`goreleaser check`), Task 4, and the Task 6 smoke release are the gates that surface these before they reach users.
