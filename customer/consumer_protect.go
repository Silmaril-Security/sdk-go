// Installed-module customer application using parallel protection; the runner copies this into an independent module.
package main

import (
	"context"
	"encoding/json"
	"errors"
	fw "github.com/Silmaril-Security/sdk-go/firewall"
	"os"
	"time"
)

func main() {
	var scenario struct {
		UserInput string `json:"user_input"`
		ToolName  string `json:"tool_name"`
		Cases     []struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"cases"`
	}
	data, err := os.ReadFile(os.Getenv("CUSTOMER_SCENARIO"))
	must(err)
	must(json.Unmarshal(data, &scenario))
	run := os.Getenv("CUSTOMER_RUN_ID")
	var prediction fw.Prediction
	client, err := fw.New(fw.Options{
		APIKey:     os.Getenv("SILMARIL_API_KEY"),
		APIURL:     os.Getenv("SILMARIL_API_URL"),
		Mode:       fw.ModeBlock,
		OnClassify: func(event fw.ClassifyEvent) { prediction = event.Result.Prediction },
	})
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	_, err = client.Classify(ctx, scenario.UserInput, fw.WithHook(fw.HookUserInput), fw.WithRequestID(run+"-user"))
	must(err)
	rows := []map[string]any{}
	for _, item := range scenario.Cases {
		id := run + "-" + item.ID
		summary, err := fw.Protect(ctx, client, item.Text,
			func(context.Context) (string, error) { return "Search performance improved; settings fixed.\n", nil },
			fw.WithHook(fw.HookToolResponse), fw.WithToolName(scenario.ToolName), fw.WithRequestID(id))
		var denied *fw.FirewallBlockedError
		blocked := errors.As(err, &denied)
		if err != nil && !blocked {
			panic("classification failed")
		}
		path := item.ID + ".summary.txt"
		if !blocked {
			must(os.WriteFile(path, []byte(summary), 0600))
		}
		_, stat := os.Stat(path)
		rows = append(rows, map[string]any{"id": item.ID, "request_id": id, "prediction": prediction, "blocked": blocked, "wrote_summary": stat == nil})
	}
	data, err = json.Marshal(map[string]any{"run_id": run, "cases": rows})
	must(err)
	must(os.WriteFile(os.Getenv("CUSTOMER_RESULT"), data, 0600))
}
func must(err error) {
	if err != nil {
		panic("customer execution failed")
	}
}
