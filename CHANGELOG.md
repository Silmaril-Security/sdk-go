# Changelog

## v1.0.0

The SDK now speaks version 2 of the classify contract. This is a breaking
release for code that reads the result; no configuration changes are needed.

- Call `POST /v2/classify`, which returns one decision per input. `APIURL` is
  unchanged: the SDK removes a trailing slash and a final `/v2/classify` or
  `/classify` path, keeps the query string, and appends `/v2/classify`. `New`
  now rejects an `APIURL` that does not parse.
- Work against runtimes without `/v2/classify`. When that endpoint answers
  HTTP 403, 404, or 405, the SDK sends the same request to `/classify`, adapts
  the response, and remembers a successful fallback for the life of the
  client. Adapted results carry the same `Action`, `Source`, `Outcome`,
  `Governance`, `ModelID`, and `Review`, with empty evidence in `Confidence`
  and `Severity`. An adapted result blocks exactly when 0.x did, on a
  `MALICIOUS` `prediction` or a governance block, so it never allows what
  `/classify` blocked. The retry policy for 408, 429, and 5xx responses is
  unchanged.
- Adapt a successful response without a `results` key as a `/classify` body
  whichever path returned it, so an intermediary that routes `/v2/classify` to
  the `/classify` handler still yields decisions; the SDK keeps calling
  `/v2/classify`.
- `BlockResult` carries `Action`, `Source`, `Confidence`, `Severity`,
  `Outcome`, `Governance`, `ModelID`, `Review`, and `Mode`. `Action`,
  `Confidence`, and `Severity` are typed strings with constants. `Source` is
  an open string, with `SourceModel` and `SourceGovernance` naming the current
  sources.
  `Outcome` is a `HarmfulOutcome`, an open type whose zero value means the
  result has no outcome.
- `BlockResult.ModelID` is the identifier of the model release that classified
  the item, for provenance; it never affects enforcement.
- Enforce on `Action` alone. `Action` is always `ActionAllow` or
  `ActionBlock`: the SDK reports any wire value other than `allow` as
  `ActionBlock`, so `Action == ActionBlock` never misses a block. Unfamiliar
  `Source`, `Confidence`, `Severity`, and `Outcome` values are returned as
  given, and unknown response fields are ignored.
- Reject a response whose `results` do not match the inputs one to one, or
  whose result has a missing or non-string `action`, before returning results
  or invoking callbacks.
- Validate returned governance evidence as v0.8.3 does on both versions: a
  present `identity_revision` or `reason` must be nonblank, and a resource
  other than an MCP tool may not return `parent_id` as an empty string.
- Remove `Prediction`, `Score`, `Threshold`, `PrimaryOutcome`,
  `OutcomeScores`, `DetectorScores`, and `DetectorCounts` from `BlockResult`,
  the `Prediction` type and its constants, and `Score` and `Threshold` from
  `FirewallBlockedError`. Blocking error strings no longer include a score.
- Remove the `PrimaryOutcome` type, its `Outcome*` constants including
  `OutcomeBenign`, `PrimaryOutcomes`, and `IsPrimaryOutcome`: an outcome now
  exists only on a model block, so there is no benign label.
  `OutcomeDescriptions` is keyed by `HarmfulOutcome` and has no benign entry.
  `HarmfulOutcome`, its constants, `HarmfulOutcomes`, and `IsHarmfulOutcome`
  are unchanged.

Migration:

| 0.x | 1.0.0 |
|---|---|
| `Prediction` (`PredictionBenign`, `PredictionMalicious`) | `Action` (`ActionAllow`, `ActionBlock`) |
| `PrimaryOutcome` field, `PrimaryOutcome` type, `Outcome*` constants | `Outcome` field, `HarmfulOutcome` type, `HarmfulOutcome*` constants |
| `OutcomeBenign` | empty `Outcome` |
| `PrimaryOutcomes()`, `IsPrimaryOutcome()` | `HarmfulOutcomes()`, `IsHarmfulOutcome()` |
| `Score`, `Threshold` | `Confidence`, `Severity` |
| wire `predictions` | wire `results` |

`Confidence` and `Severity` are not a renamed score. They describe the
Firewall's assessment of the item and are set only when that assessment is the
reason for the block; they are empty on an allow, on a block that came from a
governance policy, and on a block the Firewall reached without that
assessment. The module path
stays `github.com/Silmaril-Security/sdk-go`, because this is the module's
first v1 release. SDK 0.x keeps working against `/classify`, which is frozen.

## v0.9.0

- Breaking: rename the tenant acceptable-use policy outcome to `abuse`.
  `OutcomeAbuse` and `HarmfulOutcomeAbuse` replace the tenant-specific
  constants, and `PrimaryOutcomes`, `HarmfulOutcomes`, and
  `OutcomeDescriptions` list `abuse` in the same position. Responses that
  still carry the previous label continue to decode as an open-ended outcome
  string.

## v0.8.3

- Match Python `str.strip()` when validating optional governance
  `identity_revision` and `reason` evidence. Omitted and null values remain
  compatible, and accepted nonblank strings remain unmodified.

## v0.8.2

- Match Python `str.strip()` when validating response outcome labels, including
  non-ASCII whitespace and separator controls. Nonblank labels remain
  unmodified, and U+FEFF remains nonblank.

## v0.8.1

- Reject missing, null, nonnumeric, or out-of-range response `score` and
  `threshold` values, and reject outcome and detector scores outside the
  inclusive range from 0 to 1.
- Correct `metadata.silmaril` handling for concrete and named Go map types
  that encode as JSON objects, preserving integer precision and rejecting
  values that do not encode as objects.
- Tighten governance response decoding: optional `identity_revision` and
  `reason` strings may be null or omitted but must be nonblank when present,
  and a resource other than an MCP tool may not return `parent_id` as an empty string.
  Nonblank evidence strings are preserved exactly.

## v0.8.0

- Add `Protect` and `ProtectWithOutput`, which run an operation while its
  input is classified. In Block mode the result is withheld until the verdict
  and a block cancels the operation's context; in Shadow and Warn the result
  returns immediately and the classification finishes in the background.
- Send classifications started by `Protect` that share
  `metadata.conversationId` in the order they were started. Background
  classifications retry once.
- Add `Options.MaxConcurrent` (default 32) and `Options.MaxQueued` (default
  64), and `Firewall.Flush` to wait for background classifications. The client
  keeps at most `MaxConcurrent` times `MaxQueued` background classifications
  across all conversations.
- `Protect` copies request metadata and the governance resource when it
  starts, sends its Block-mode output check through the same ordered queue,
  and stops waiting for its turn when its context is done.

## v0.7.7

- Reject null elements in `outcome_scores`, `detector_scores`, and
  `detector_counts` before returning results or invoking callbacks for single
  and batch classifications. Optional whole maps may still be null or omitted;
  valid zero values and future labels remain accepted.

## v0.7.6

- Reject negative `detector_counts` values before returning classification
  results or invoking callbacks. Nil and empty maps, nonnegative values, and
  future detector labels remain accepted.

## v0.7.5

- Add optional `review` on `Classify` and `ClassifyBatch`: `ReviewStandard`
  (`standard`) or `ReviewDeep` (`deep`). An omitted client option and omitted
  per-call option leave the wire field unset so tenant AppConfig
  `threat_judge.enabled` remains authoritative. Per-call `WithReview` /
  `WithBatchReview` override `Options.Review`.
- Verify the top-level response acknowledgement before callbacks or blocking
  errors. A missing, non-string, or mismatched acknowledgement returns
  `ReviewCompatibilityError`. That error does not schedule another attempt.

## v0.7.4

- Preserve optional governance response evidence for single and batch
  classifications: the canonical resource, identity revision, and open-ended
  reason string. Legacy responses that omit or null these fields remain
  compatible.

## v0.7.3

- Send typed governance resources in the runtime's top-level `resource` and
  aligned `resources` fields, preserving compatibility attribution metadata.
- Reject invalid canonical resource references before submitting a request.
  Caller-supplied agent metadata remains attribution, not authenticated identity.

## v0.7.2

- Corrects the mode documentation for the current `/classify` wire contract:
  responses omit mode, so mode-less calls leave `BlockResult.Mode` empty and
  retain the SDK's local Block enforcement fallback.
- Documents that callers must explicitly select `ModeShadow` or `ModeWarn` for
  observation-only behavior, or `ModeBlock` for explicit enforcement. Runtime
  behavior is unchanged.

## v0.7.1

- Clarifies that a nil `WithBatchMetadata` entry contributes no caller fields
  while still including SDK-owned provenance in `metadata.silmaril`. Runtime
  metadata behavior is unchanged.

## v0.7.0

- Add typed governance context for single and batch classifications. The SDK
  sends `agent` and governed `resource` on `metadata.silmaril.governance`.
  Hook stays a separate request field, and the server owns the authenticated
  principal.
- Normalize response governance decisions and treat an explicit governance block
  as blocked, alongside malicious predictions.
- Preserve compatibility with older responses that omit governance.

## v0.6.1

- Documents that one `Firewall` may be shared by goroutines: `Classify` and
  `ClassifyBatch` already accept per-call contexts, isolate request state, and
  honor cancellation without a separate async API.
- Records caller responsibility for concurrent safety of `OnClassify`,
  caller-owned metadata, and any custom HTTP transport.
- Adds httptest coverage for overlapping calls, out-of-order completion,
  per-call metadata and request id isolation, batch item order, and sibling
  isolation when one context is canceled during HTTP or retry sleep.

## v0.6.0

- Adds the existing `shadow | warn | block` request mode contract to single
  and batch classification, with backend control when mode is omitted.
- Returns and enforces the backend-resolved effective mode on current-backend
  results.
- Keeps an explicit request mode authoritative when a legacy or mixed-version
  backend omits or disagrees about `mode`. When both request and response omit
  mode, leaves the result mode empty so integrations can preserve their pre-0.6
  behavior without increasing enforcement.
- Retains `WithShadowMode` and `WithBatchShadowMode`: true requests Shadow,
  false requests Block, and explicit mode options take precedence.
- Keeps `Options.ShadowMode` source-compatible for Shadow; use `ModeBlock` for
  an explicit client-level Block override because Go cannot distinguish an
  omitted bool field from an explicit false value.

## v0.5.1

- Adds typed support for `code_generation`, `story_script_generation`,
  `game_generation`, `website_generation`, `traditional_ai_abuse`, and the
  tenant acceptable-use policy outcome now named `abuse`.
- Extends ordered outcome collections, descriptions, validators, normalization
  fixtures, exports, and documentation without changing the `/classify` wire
  shape.

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
