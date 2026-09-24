// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

// Package firewall provides the Silmaril Firewall Go client.
//
// The client calls a Silmaril /classify endpoint to evaluate user input, tool
// calls, tool responses, model output, or system prompt content before an AI
// application continues execution. Classify and ClassifyBatch enforce backend
// blocking decisions by default and return FirewallBlockedError or
// BatchFirewallBlockedError when the Firewall blocks a request. Enable shadow
// mode to observe decisions without interrupting traffic.
//
// The package is dependency-free outside the Go standard library. Long inputs
// are sent as complete logical events, and SDK metadata carries one event ID
// while the backend owns sequence ordering and token-window processing. One
// Firewall is safe to share across goroutines; each Classify or ClassifyBatch
// call uses its own context and request state. Callers own concurrent safety
// of OnClassify, metadata maps, and any custom HTTP transport.
package firewall
