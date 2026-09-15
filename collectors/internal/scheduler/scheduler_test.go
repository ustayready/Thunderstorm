package scheduler

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
	"thunderstorm/collector/internal/registry"
)

// mockInvoker returns canned records and records how each op was called, so we
// can assert bindings resolved correctly.
type mockInvoker struct {
	mu    sync.Mutex
	calls map[string][]map[string]string // op → list of params it was called with
}

func newMock() *mockInvoker { return &mockInvoker{calls: map[string][]map[string]string{}} }

func (m *mockInvoker) Invoke(_ context.Context, op, _ string, params map[string]string) ([]map[string]any, error) {
	m.mu.Lock()
	cp := map[string]string{}
	for k, v := range params {
		cp[k] = v
	}
	m.calls[op] = append(m.calls[op], cp)
	m.mu.Unlock()

	switch op {
	case "lambda:ListFunctions":
		return []map[string]any{
			{"function_name": "fn-a", "function_arn": "arn:fn-a", "role_arn": "role-a"},
			{"function_name": "fn-b", "function_arn": "arn:fn-b", "role_arn": "role-b"},
		}, nil
	case "lambda:GetFunction":
		name := params["FunctionName"]
		return []map[string]any{{"code_location": "https://code/" + name, "code_sha256": "sha-" + name}}, nil
	case "http:GetBlob":
		return []map[string]any{{"code_size": 42, "code_blob_sha": "blob", "evidence_ref": "blob://x"}}, nil
	}
	return nil, nil
}

func lambdaRes() *registry.ResourceType {
	return &registry.ResourceType{
		ResourceType: "aws:lambda:function", NodeType: "ServerlessFunction", Scope: "regional",
		Enumerate: registry.Enumerate{
			Operation: "lambda:ListFunctions", IDField: "function_name", ARNField: "function_arn",
			Attributes: []string{"role_arn"}, Yields: []string{"function_name"},
		},
		Detail: []registry.Detail{
			{Operation: "lambda:GetFunction", Bind: map[string]string{"FunctionName": "$function_name"}, Capture: []string{"code_location", "code_sha256"}},
			{Operation: "http:GetBlob", Bind: map[string]string{"url": "$code_location"}, Capture: []string{"code_size", "evidence_ref"}},
		},
	}
}

func TestBindingResolutionChain(t *testing.T) {
	dir := t.TempDir()
	b, err := output.New(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	mock := newMock()
	s := New(mock, func(error) string { return "error" }, led, b, 8)

	res := lambdaRes()
	seed := Task{
		ID:    "us-east-1/aws:lambda:function/lambda:ListFunctions",
		Scope: model.Scope{Provider: "aws", Account: "123", Region: "us-east-1"},
		Res:   res, Op: res.Enumerate.Operation, Step: -1,
		Params: map[string]string{}, Record: map[string]any{},
	}
	n := s.Run(context.Background(), []Task{seed})
	b.Close()

	if n != 2 {
		t.Fatalf("expected 2 artifacts, got %d", n)
	}

	// GetFunction must have been called once per function, with the bound name.
	got := boundValues(mock, "lambda:GetFunction", "FunctionName")
	if want := []string{"fn-a", "fn-b"}; !equal(got, want) {
		t.Errorf("GetFunction FunctionName bindings = %v, want %v", got, want)
	}
	// http:GetBlob must have been bound to each function's code_location.
	urls := boundValues(mock, "http:GetBlob", "url")
	if want := []string{"https://code/fn-a", "https://code/fn-b"}; !equal(urls, want) {
		t.Errorf("http:GetBlob url bindings = %v, want %v", urls, want)
	}

	// The emitted artifacts must carry enumerate + captured detail fields.
	arts := readArtifacts(t, filepath.Join(dir, "inventory", "aws-lambda-function.ndjson"))
	if len(arts) != 2 {
		t.Fatalf("expected 2 artifacts on disk, got %d", len(arts))
	}
	for _, a := range arts {
		if a.NodeType != "ServerlessFunction" {
			t.Errorf("node_type = %q", a.NodeType)
		}
		if a.Attributes["role_arn"] == nil {
			t.Errorf("%s missing role_arn (enumerate attr)", a.NativeID)
		}
		if a.Attributes["code_location"] == nil {
			t.Errorf("%s missing code_location (detail capture)", a.NativeID)
		}
		if a.EvidenceRef != "blob://x" {
			t.Errorf("%s evidence_ref = %q", a.NativeID, a.EvidenceRef)
		}
	}
}

func TestUnresolvedBindingIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	b, _ := output.New(dir, true)
	led := ledger.New()
	// mock whose ListFunctions omits function_name → GetFunction binding can't resolve.
	mock := &mockInvoker{calls: map[string][]map[string]string{}}
	res := lambdaRes()
	s := New(stubInvoker(func(op string) []map[string]any {
		if op == "lambda:ListFunctions" {
			return []map[string]any{{"function_arn": "arn:x"}} // no function_name
		}
		return nil
	}), func(error) string { return "error" }, led, b, 4)
	_ = mock
	seed := Task{ID: "r/aws:lambda:function/lambda:ListFunctions",
		Scope: model.Scope{Provider: "aws", Account: "1", Region: "r"},
		Res:   res, Op: res.Enumerate.Operation, Step: -1,
		Params: map[string]string{}, Record: map[string]any{}}
	s.Run(context.Background(), []Task{seed})
	b.Close()
	// The run must not panic; a skipped:unresolved_binding row must exist.
	found := false
	for _, row := range led.Rows() {
		if row.Status == model.OutcomeSkipped && row.Reason == "unresolved_binding" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a skipped:unresolved_binding ledger row")
	}
}

// stubInvoker adapts a func to the Invoker interface.
type stubInvoker func(op string) []map[string]any

func (f stubInvoker) Invoke(_ context.Context, op, _ string, _ map[string]string) ([]map[string]any, error) {
	return f(op), nil
}

// erroringInvoker fails one op and succeeds on another — for the bulkhead test.
type erroringInvoker struct{}

func (erroringInvoker) Invoke(_ context.Context, op, _ string, _ map[string]string) ([]map[string]any, error) {
	switch op {
	case "boom:List":
		return nil, errBoom
	case "ok:List":
		return []map[string]any{{"native_id": "x", "arn": "arn:x"}}, nil
	}
	return nil, nil
}

var errBoom = fmt.Errorf("AccessDenied: not authorized")

// TestBulkheadFailureIsolation is the M2 foolproofness acceptance test: one
// task erroring must NOT crash the run or block others — it becomes a ledger
// row (denied), while sibling tasks still collect. Coverage stays complete.
func TestBulkheadFailureIsolation(t *testing.T) {
	dir := t.TempDir()
	b, _ := output.New(dir, true)
	led := ledger.New()
	classify := func(err error) string {
		if err != nil && strings.Contains(err.Error(), "AccessDenied") {
			return "denied"
		}
		return "error"
	}
	s := New(erroringInvoker{}, classify, led, b, 8)

	boom := &registry.ResourceType{ResourceType: "aws:boom:thing", Scope: "global",
		Enumerate: registry.Enumerate{Operation: "boom:List", IDField: "native_id", ARNField: "arn"}}
	okRes := &registry.ResourceType{ResourceType: "aws:ok:thing", NodeType: "Thing", Scope: "global",
		Enumerate: registry.Enumerate{Operation: "ok:List", IDField: "native_id", ARNField: "arn"}}

	seeds := []Task{
		{ID: "global/aws:boom:thing/boom:List", Scope: model.Scope{Provider: "aws", Account: "1", Global: true},
			Res: boom, Op: "boom:List", Step: -1, Params: map[string]string{}, Record: map[string]any{}},
		{ID: "global/aws:ok:thing/ok:List", Scope: model.Scope{Provider: "aws", Account: "1", Global: true},
			Res: okRes, Op: "ok:List", Step: -1, Params: map[string]string{}, Record: map[string]any{}},
	}
	n := s.Run(context.Background(), seeds) // must not panic
	b.Close()

	if n != 1 {
		t.Errorf("expected 1 artifact from the healthy task, got %d", n)
	}
	if !led.IntegrityOK() {
		t.Errorf("ledger integrity should hold — every task reached a terminal outcome")
	}
	var sawDenied bool
	for _, r := range led.Rows() {
		if r.ResourceType == "aws:boom:thing" && r.Status == model.OutcomeDenied {
			sawDenied = true
		}
	}
	if !sawDenied {
		t.Errorf("the failing task should be recorded as denied, not lost")
	}
}

func boundValues(m *mockInvoker, op, param string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, c := range m.calls[op] {
		out = append(out, c[param])
	}
	sort.Strings(out)
	return out
}

func readArtifacts(t *testing.T, path string) []model.Artifact {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var arts []model.Artifact
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var a model.Artifact
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		arts = append(arts, a)
	}
	return arts
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
