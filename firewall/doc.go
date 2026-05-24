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
// are chunked client-side, and SDK metadata is attached to requests so the
// backend can reconstruct batches and chunks when applying tenant policy.
package firewall
