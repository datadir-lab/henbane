# Contributing to Henbane

Thanks for your interest in Henbane. This project has a few firm constraints —
reading them first will save a round-trip in review.

## Ground rules

- **Zero third-party runtime dependencies.** The module must build on the Go
  standard library alone, plus the single allowlisted config dependency
  (`gopkg.in/yaml.v3`). New imports outside the allowlist fail an architecture
  test by design. Dev/CI tools invoked via `go run`/`go install` are fine —
  they are not compiled into the binary.
- **Hexagonal architecture.** `internal/ports` and the domain/core packages stay
  transport-pure: no `net/http`, no adapters, no config, no client-IP code.
  `internal/arch` enforces this.
- **Zero-trust mindset.** Validate and bound every external input, fail
  closed/safe, and never let untrusted data into logs or decisions unsanitized.
  Anything attacker-sized needs an explicit bound.
- **TDD.** Write the failing test first, then the minimal code to pass it.

## Workflow

1. Branch from `main`.
2. Make focused changes with tests.
3. Run the local checks below — they mirror CI.
4. Open a PR into `main`. Keep it scoped to one logical change.

## Local checks

```sh
gofmt -l .                                   # must print nothing
go vet ./...
go test -race -count=1 ./...
go test -count=1 ./internal/arch/...          # architecture + dependency allowlist
go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...
go build ./...
```

[Lefthook](https://github.com/evilmartians/lefthook) runs the fast subset on
`pre-commit` and the full suite plus `govulncheck` on `pre-push`:

```sh
lefthook install
```

## Commit messages

Commits follow **[Conventional Commits](https://www.conventionalcommits.org/)**
(enforced by `conform`): `type(scope): summary`, header ≤ 72 chars, lowercase,
scope matching `[a-z0-9/-]+`. Allowed types: `feat`, `fix`, `docs`, `style`,
`refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

## License

By contributing, you agree that your contributions are licensed under the
project's [GNU AGPL-3.0 License](LICENSE).
