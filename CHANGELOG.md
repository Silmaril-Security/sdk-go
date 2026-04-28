# Changelog

## Unreleased

- Honors explicit zero thresholds by making `Options.Threshold` optional.
- Replaces mutable `DefaultHookThresholds` package state with a copy-returning
  function.
- Trusts server predictions, carries the applied threshold on `BlockResult`,
  and exposes `ClassifyBatch`.
- Adds full-jitter retry backoff, retry body draining, bounded API error body
  reads, and final network error wrapping.

## v0.1.5

- Removes the unneeded `PromptBlockedError` from the low-level SDK.

## v0.1.4

- Removes extra exported `Firewall` helper methods from the public API.
- Removes the unused `ShadowMode` option from the low-level client.

## v0.1.3

- Publishes the SDK from the public `github.com/Silmaril-Security/sdk-go`
  module path.
- Uses a source-available SDK license.
- Refines public positioning around self-healing prompt injection defense.

## v0.1.2

- Initial standalone Go module packaging.
- Exposes a single `Classify` API with consistent client-side chunking.
- Applies configured thresholds and hook-specific thresholds.
- Adds transient retry handling for transport failures and retryable HTTP responses.
