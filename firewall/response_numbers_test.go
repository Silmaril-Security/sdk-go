// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClassifyRequiresNumericVerdictFields(t *testing.T) {
	for _, tc := range []struct {
		name, fields, invalidField string
		score, threshold           float64
	}{
		{name: "missing score", fields: `"threshold":0.5`, invalidField: "score"},
		{name: "missing threshold", fields: `"score":0.1`, invalidField: "threshold"},
		{name: "null score", fields: `"score":null,"threshold":0.5`, invalidField: "score"},
		{name: "null threshold", fields: `"score":0.1,"threshold":null`, invalidField: "threshold"},
		{name: "string score", fields: `"score":"0.1","threshold":0.5`, invalidField: "score"},
		{name: "string threshold", fields: `"score":0.1,"threshold":"0.5"`, invalidField: "threshold"},
		{name: "overflow score", fields: `"score":1e400,"threshold":0.5`, invalidField: "score"},
		{name: "overflow threshold", fields: `"score":0.1,"threshold":1e400`, invalidField: "threshold"},
		{name: "negative score", fields: `"score":-0.1,"threshold":0.5`, invalidField: "score"},
		{name: "threshold above one", fields: `"score":0.1,"threshold":1.1`, invalidField: "threshold"},
		{name: "inclusive bounds", fields: `"score":0,"threshold":1`, score: 0, threshold: 1},
	} {
		for _, entry := range []struct {
			name  string
			batch bool
		}{{"single", false}, {"batch", true}} {
			t.Run(tc.name+"/"+entry.name, func(t *testing.T) {
				body := `{"prediction":"BENIGN",` + tc.fields + `}`
				if entry.batch {
					body = `{"predictions":[` + body + `]}`
				}
				callbacks := 0
				fw, err := New(Options{
					APIKey: "test", APIURL: "https://firewall.test/classify",
					HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
					})},
					OnClassify: func(ClassifyEvent) { callbacks++ },
				})
				if err != nil {
					t.Fatal(err)
				}
				var result BlockResult
				if entry.batch {
					var results []BlockResult
					results, err = fw.ClassifyBatch(context.Background(), []string{"hello"})
					if err == nil {
						result = results[0]
					}
				} else {
					result, err = fw.Classify(context.Background(), "hello")
				}
				if tc.invalidField != "" {
					want := "firewall: response " + tc.invalidField + " must be a number between 0 and 1"
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("classification error = %v, want %q", err, want)
					}
					if callbacks != 0 {
						t.Errorf("OnClassify ran %d times for an invalid verdict", callbacks)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if result.Score != tc.score || result.Threshold != tc.threshold || callbacks != 1 {
					t.Fatalf("result = %+v, callbacks = %d", result, callbacks)
				}
			})
		}
	}
}
