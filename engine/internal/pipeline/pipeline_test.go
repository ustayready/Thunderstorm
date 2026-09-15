package pipeline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"thunderstorm/engine/internal/bundle"
	"thunderstorm/engine/internal/graph"
	"thunderstorm/engine/internal/model"
)

// writeBundle materializes a minimal Evidence Bundle on disk for the golden test.
func writeBundle(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, "full")
	mustMk(t, filepath.Join(full, "inventory"))
	mustMk(t, filepath.Join(full, "facts"))

	// Inventory: a user, a role, and a secret.
	write(t, filepath.Join(full, "inventory", "iam.ndjson"),
		`{"provider":"aws","account":"111111111111","scope":{"provider":"aws","account":"111111111111","global":true},"resource_type":"aws:iam:user","node_type":"HumanIdentity","native_id":"alice","arn":"arn:aws:iam::111111111111:user/alice"}
{"provider":"aws","account":"111111111111","scope":{"provider":"aws","account":"111111111111","global":true},"resource_type":"aws:iam:role","node_type":"Role","native_id":"app","arn":"arn:aws:iam::111111111111:role/app"}`)
	write(t, filepath.Join(full, "inventory", "secret.ndjson"),
		`{"provider":"aws","account":"111111111111","scope":{"provider":"aws","account":"111111111111","region":"us-east-1"},"resource_type":"aws:secretsmanager:secret","node_type":"Secret","native_id":"db","arn":"arn:aws:secretsmanager:us-east-1:111111111111:secret:db"}`)

	// Facts:
	//  - trust: alice can assume role/app
	//  - managed policy grants secretsmanager:GetSecretValue, attached to role/app
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}]}`
	polDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	write(t, filepath.Join(full, "facts", "trust_policy.ndjson"),
		`{"kind":"trust_policy","edge_hint":"CanAssume","provider":"aws","scope":{"provider":"aws","account":"111111111111","global":true},"source":"arn:aws:iam::111111111111:role/app","attributes":{"document":`+jsonString(trust)+`}}`)
	write(t, filepath.Join(full, "facts", "managed_policy.ndjson"),
		`{"kind":"managed_policy","edge_hint":"HasPermission","provider":"aws","scope":{"provider":"aws","account":"111111111111","global":true},"source":"arn:aws:iam::111111111111:policy/readsecret","attributes":{"document":`+jsonString(polDoc)+`}}`)
	write(t, filepath.Join(full, "facts", "membership.ndjson"),
		`{"kind":"membership","edge_hint":"HasPolicy","provider":"aws","scope":{"provider":"aws","account":"111111111111","global":true},"source":"arn:aws:iam::111111111111:role/app","target":"arn:aws:iam::111111111111:policy/readsecret"}`)

	return root
}

// TestGoldenAttackChain: alice can assume role/app, which can read secret db.
// The pipeline must (1) evaluate role/app -> CanReadSecret(db) from the attached
// managed policy, (2) build CanAssume(alice -> role/app) from the trust doc, and
// (3) DERIVE CanReadSecret(alice -> db) by inheritance through CanAssume.
func TestGoldenAttackChain(t *testing.T) {
	root := writeBundle(t)
	b, err := bundle.Load(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	nodes, edges, stats := Run(b, time.Now())
	if stats.PermEdges == 0 {
		t.Fatalf("expected a permission edge (role -> secret), got none")
	}

	aliceID := "aws|111111111111|aws:iam:user|alice"
	secretID := "aws|111111111111|aws:secretsmanager:secret|db"

	// The evaluator must grant the role the secret read.
	if findEdge(edges, "CanReadSecret", "iam:role|app", "secret|db") == nil {
		t.Errorf("evaluator missed role/app -> CanReadSecret(db)")
	}
	// The base graph must have CanAssume(alice -> role/app).
	if findEdge(edges, "CanAssume", "iam:user|alice", "iam:role|app") == nil {
		t.Errorf("missing CanAssume(alice -> role/app)")
	}
	// The derivation must chain them: CanReadSecret(alice -> db), nature=derived.
	chain := findEdge(edges, "CanReadSecret", "iam:user|alice", "secret|db")
	if chain == nil {
		t.Fatalf("expected DERIVED CanReadSecret(alice -> db); edges:\n%s", dump(edges))
	}
	if chain.Nature != model.NatureDerived {
		t.Errorf("chain nature = %s want derived", chain.Nature)
	}
	if len(chain.DerivedFrom) < 2 {
		t.Errorf("chain must cite its contributors, got %v", chain.DerivedFrom)
	}

	// And the path query must find it.
	g := graph.New(nodes, edges, false)
	path, _ := g.ShortestPath(aliceID, secretID)
	if path == nil {
		t.Errorf("path query found no alice -> secret path")
	}
}

// --- helpers ---

func findEdge(edges []model.Edge, typ, srcSub, tgtSub string) *model.Edge {
	for i := range edges {
		e := edges[i]
		if e.Type == typ && sub(e.Source, srcSub) && sub(e.Target, tgtSub) {
			return &edges[i]
		}
	}
	return nil
}

func sub(s, want string) bool {
	if want == "" {
		return true
	}
	for i := 0; i+len(want) <= len(s); i++ {
		if s[i:i+len(want)] == want {
			return true
		}
	}
	return false
}

func dump(edges []model.Edge) string {
	out := ""
	for _, e := range edges {
		out += "  " + e.Type + " " + e.Source + " -> " + e.Target + " (" + e.Nature + ")\n"
	}
	return out
}

func jsonString(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		default:
			b = append(b, string(r)...)
		}
	}
	b = append(b, '"')
	return string(b)
}

func mustMk(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
