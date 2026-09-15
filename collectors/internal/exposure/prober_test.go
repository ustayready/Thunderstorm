package exposure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
)

func writeInventory(t *testing.T, dir, resourceType string, arts ...model.Artifact) {
	t.Helper()
	b, _ := output.New(dir, false)
	shard := "inventory/" + strings.ReplaceAll(resourceType, ":", "-") + ".ndjson"
	for _, a := range arts {
		if err := b.AppendJSON(shard, a); err != nil {
			t.Fatal(err)
		}
	}
	b.Close()
}

// TestReadAPIGateNeverInvokesWriteRecipe: a non-read_api site must be a surface
// and its operation NEVER fetched — even if a fetcher is (wrongly) registered.
func TestReadAPIGateNeverInvokesWriteRecipe(t *testing.T) {
	dir := t.TempDir()
	b, _ := output.New(dir, false)
	led := ledger.New()
	invoked := false
	fetchers := FetcherSet{
		"DangerousWrite": {ResourceType: "aws:thing:x", Fetch: func(context.Context, string, map[string]any) (any, error) {
			invoked = true
			return nil, nil
		}},
	}
	sites := []Site{
		{ID: "danger-write", Service: "thing", Read: Read{AccessMode: "write_only_input", Operation: "DangerousWrite"}},
		{ID: "danger-create", Service: "thing", Read: Read{AccessMode: "creation_response_only", Operation: "DangerousWrite"}},
	}
	sum := NewProber(fetchers, nil, nil, func(error) string { return "error" }, led, b, dir, "salt", "acct", 8).
		Run(context.Background(), sites)
	b.Close()

	if invoked {
		t.Fatal("SAFETY VIOLATION: a non-read_api recipe was invoked")
	}
	if sum.Surfaces != 2 || sum.ReadAPI != 0 {
		t.Errorf("expected 2 surfaces / 0 read_api, got %+v", sum)
	}
}

// TestProbeDetectsRedactsAndExtractsNestedPath exercises the fetcher + nested
// response-path extraction + redaction together.
func TestProbeDetectsRedactsAndExtractsNestedPath(t *testing.T) {
	dir := t.TempDir()
	writeInventory(t, dir, "aws:cloudformation:stack",
		model.Artifact{NativeID: "prod", ARN: "arn:stack:prod", Scope: model.Scope{Region: "us-east-1"}},
	)
	b, _ := output.New(dir, false)
	led := ledger.New()

	const rawSecret = "AKIAIOSFODNN7EXAMPLE"
	// DescribeStacks returns a nested structure; the site path digs into it.
	fetchers := FetcherSet{
		"DescribeStacks": {ResourceType: "aws:cloudformation:stack", Fetch: func(context.Context, string, map[string]any) (any, error) {
			return map[string]any{
				"Stacks": []any{
					map[string]any{"Parameters": []any{
						map[string]any{"ParameterValue": rawSecret},
						map[string]any{"ParameterValue": "not-a-secret-plain"},
					}},
				},
			}, nil
		}},
	}
	sites := []Site{{ID: "aws-cfn-stack-parameter-value", Service: "cloudformation",
		Location:  "DescribeStacks.Stacks[].Parameters[].ParameterValue",
		EmitsHint: "ContainsCredential", Severity: "critical",
		Read: Read{AccessMode: "read_api", Operation: "DescribeStacks",
			ResponsePath: "Stacks[].Parameters[].ParameterValue"}}}

	sum := NewProber(fetchers, nil, nil, func(error) string { return "error" }, led, b, dir, "run-salt", "acct", 8).
		Run(context.Background(), sites)
	b.Close()

	if sum.Hits != 1 { // only the AKIA value looks like a secret; the plain value is filtered
		t.Fatalf("expected 1 hit from nested path (AKIA only), got %d", sum.Hits)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "exposure", "hits.ndjson"))
	// The captured value IS the loot — a pentester needs the real value to use it, so it
	// is stored in `value`; `value_ref` remains a salted-hash fingerprint (dedup/integrity).
	if !strings.Contains(string(data), rawSecret) {
		t.Fatal("expected the captured raw value to be stored in the hit")
	}
	if !strings.Contains(string(data), "sha256:") || !strings.Contains(string(data), "ContainsCredential") {
		t.Error("hit should carry a value_ref fingerprint and the emits_hint")
	}
}
