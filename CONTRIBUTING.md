# Contributing

## Development

Run the standard validation locally before opening a PR:

```sh
make check
```

The SDK intentionally has no third-party runtime dependencies. Keep the public
surface small and prefer standard-library implementations unless there is a
clear customer benefit.

## Releases

1. Update `VERSION` and `CHANGELOG.md`.
2. Run `make check`.
3. Create a semantic version tag:

```sh
git tag vX.Y.Z
git push origin vX.Y.Z
```

