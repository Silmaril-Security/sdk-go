# Changelog

## Unreleased

## v0.5.0

- Sends every `Classify` input as one complete event without client chunking.
- Preserves exact `metadata.conversationId` and emits one
  `metadata.silmaril.request_id` per event.
- Requires backend `prediction` for enforcement while preserving optional
  outcome scores.

## v0.4.1

- Adds typed firewall outcome constants, ordered outcome accessors,
  descriptions, validation helpers, and response normalization.
- Types `BlockResult.PrimaryOutcome`, `OutcomeScores`, `DetectorScores`, and
  `DetectorCounts` around the canonical outcome taxonomy.
- Documents simple outcome routing examples using `WithShadowMode(true)`.

## v0.4.0

- Moves score-threshold decisions fully to the Firewall backend. The SDK no
  longer sends a client-side `threshold` field, while `BlockResult.Threshold`
  continues to report the backend-applied value for diagnostics.
- Adds SDK reconstruction metadata under `metadata.silmaril`, including
  language, SDK version, request id, input index, chunk index, and chunk count.
- Adds `WithRequestID` and `WithBatchRequestID` for callers that need to
  correlate SDK metadata with their own request traces.
- Renames blocking errors to `FirewallBlockedError` and
  `BatchFirewallBlockedError`, with the previous `PromptBlockedError` and
  `BatchPromptBlockedError` names retained as deprecated aliases for one
  release.
- Adds GitHub Actions CI and release automation for formatting, tidy, vet,
  race tests, semantic version tags, Go module proxy warming, and GitHub
  release creation.

## v0.3.2

- Adds request metadata support to `Classify` and `ClassifyBatch`, including
  chunk fanout propagation.

## v0.3.1

- Raises the SDK long-input cap to 81,920 estimated tokens while preserving
  400-token chunk windows and 64-token overlap.

## v0.3.0

- Removes customer-facing threshold configuration from `Options` and batch
  calls.
- Adds internal adaptive thresholds based on chunk or batch size, capped at
  `0.9`, while preserving `BlockResult.Threshold` diagnostics.
- Updates README guidance for automatic thresholding and migration from removed
  threshold knobs.

## v0.1.7

- Honors explicit zero thresholds by making `Options.Threshold` optional.
- Replaces mutable `DefaultHookThresholds` package state with a copy-returning
  function.
- Trusts server predictions, carries the applied threshold on `BlockResult`,
  and exposes `ClassifyBatch`.
- Adds full-jitter retry backoff, retry body draining, bounded API error body
  reads, and final network error wrapping.
- Fans out long-input `Classify` chunks as bounded parallel single-text
  requests with `Options.ChunkConcurrency`.
- Moves the SDK package into `firewall/`, with import path
  `github.com/Silmaril-Security/sdk-go/firewall`.
- Makes `Classify` and `ClassifyBatch` enforce thresholds by default, with
  client-level and per-call shadow mode, `ClassifyEvent`,
  `PromptBlockedError`, and `BatchPromptBlockedError`.

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
