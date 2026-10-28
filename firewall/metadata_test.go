// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"os"
	"strings"
	"testing"
)

func TestSDKVersionMatchesVersionFile(t *testing.T) {
	data, err := os.ReadFile("../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if version := strings.TrimSpace(string(data)); version != SDKVersion {
		t.Fatalf("VERSION = %q, SDKVersion = %q", version, SDKVersion)
	}
}
