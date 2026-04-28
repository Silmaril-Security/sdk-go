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
- Keep `Classify` as the single public classification API.
- Long inputs must be chunked client-side with the same constants as the Python
  and TypeScript SDKs.
- Do not commit API keys, tenant-specific benchmark notebooks, or deployment
  credentials.

