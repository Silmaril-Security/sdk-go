# Silmaril Firewall Go SDK

This repository contains the standalone Go SDK for Silmaril Firewall.

## Commands

```sh
go test ./...
go test -race ./...
go vet ./...
gofmt -w .
go mod tidy
```

## Guidelines

- Keep the SDK standard-library only.
- Preserve the classify wire contract: the SDK calls `POST /v2/classify` and
  falls back to the frozen `POST /classify` only on HTTP 403, 404, or 405,
  adapting that response. A successful body without a `results` key is a
  `/classify` body whichever path returned it and goes through the same
  adapter. `firewall/testdata/cases.json` and `SHA256SUMS` are vendored
  unchanged from the Firewall repository's `contracts/classify/v2/`; never
  edit them by hand.
- Enforce only on `action`: any value other than `allow` is a block and is
  reported as `ActionBlock`. `source`, `confidence`, `severity`, `outcome`, and
  `model_id` are evidence and are passed through as given.
- Keep public SDK code under `firewall/`. Package-level Go examples are allowed
  when explicitly requested and when they use generic, safe-to-publish data.
  Do not add runnable samples, demos, notebooks, tenant-specific examples, or
  live-service walkthroughs to this public repo unless explicitly requested.
- Keep `Classify`, `ClassifyBatch`, and `Protect` as the public classification
  APIs. `Protect` runs a caller's operation beside `Classify`; it adds no new
  wire shape.
- Send each complete sanitized logical event in one request; the Firewall
  backend owns token-window processing and sequence ordering.
- Do not commit API keys, tenant-specific benchmark notebooks, or deployment
  credentials.
