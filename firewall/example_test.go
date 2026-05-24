// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Silmaril-Security/sdk-go/firewall"
)

func ExampleFirewall_Classify() {
	fw, err := firewall.New(firewall.Options{
		APIKey: os.Getenv("SILMARIL_API_KEY"),
		APIURL: os.Getenv("SILMARIL_API_URL"),
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := fw.Classify(
		context.Background(),
		"Summarize the attached deployment notes.",
		firewall.WithHook(firewall.HookUserInput),
		firewall.WithMetadata(firewall.ClassificationMetadata{
			"app": map[string]any{
				"request_id": "req-123",
			},
		}),
	)
	if err != nil {
		var blocked *firewall.FirewallBlockedError
		if errors.As(err, &blocked) {
			fmt.Printf("blocked at %.4f\n", blocked.Score)
			return
		}
		log.Fatal(err)
	}

	fmt.Printf("prediction: %s\n", result.Prediction)
}
