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
- Preserve the `/classify` API Gateway wire contract.
- Keep public SDK code under `firewall/`. Package-level Go examples are allowed
  when explicitly requested and when they use generic, safe-to-publish data.
  Do not add runnable samples, demos, notebooks, tenant-specific examples, or
  live-service walkthroughs to this public repo unless explicitly requested.
- Keep `Classify` and `ClassifyBatch` as the public classification APIs.
- Long inputs must be chunked client-side with the same constants as the Python
  and TypeScript SDKs.
- Do not commit API keys, tenant-specific benchmark notebooks, or deployment
  credentials.
