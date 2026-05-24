# Contributing

Thanks for helping improve the Silmaril Firewall Go SDK. This repository is
public and source-available, not permissive open source; contributions must be
compatible with the license in [LICENSE](LICENSE).

## Prerequisites

- Go 1.22 or later.
- GitHub CLI if you are publishing branches or pull requests.
- No private Silmaril API key is required for unit tests.

## Development

Run the standard validation locally before opening a PR:

```sh
make check
```

The SDK intentionally has no third-party runtime dependencies. Keep the public
surface small and prefer standard-library implementations unless there is a
clear user benefit.

Use local test servers and synthetic data in tests. Do not add tenant-specific
names, customer prompts, live service endpoints, API keys, internal benchmark
fixtures, or environment-specific examples. Runnable examples belong in public
docs or package-level examples only when they are generic and safe to publish.

## Pull Request Checklist

- Update `README.md`, `CHANGELOG.md`, and package comments when behavior or
  public API changes.
- Keep exported identifiers documented and visible in `go doc`.
- Run `go mod tidy` and commit any expected module-file changes.
- Run `test -z "$(gofmt -l .)"`, `go vet ./...`, and `go test -race ./...`.
- Stage only intended files and keep unrelated local changes out of the PR.
- Use a draft PR while the change is still being validated.

## Releases

1. Update `VERSION` and add a matching `CHANGELOG.md` section.
2. Run `make check`.
3. Create a semantic version tag:

```sh
git tag vX.Y.Z
git push origin vX.Y.Z
```

The release workflow verifies the pushed tag against `VERSION`, runs race
tests, warms the public Go module proxy, and creates the GitHub release.
