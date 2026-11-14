<!-- Keep PRs scoped to one logical change. -->

## What and why

<!-- What does this change do, and what problem does it solve? -->

## Checklist

- [ ] Tests added/updated and `go test -race -count=1 ./...` passes
- [ ] `gofmt`, `go vet`, and `staticcheck` are clean
- [ ] Architecture/allowlist tests pass (`go test -count=1 ./internal/arch/...`)
- [ ] No new third-party runtime dependency (or the allowlist is updated with rationale)
- [ ] Zero-trust: external inputs are validated and bounded; fails closed
- [ ] Conventional Commit message(s)
