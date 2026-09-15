package redact

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// realTokens are identifiers seeded into the fixture that must NOT survive in the output.
var realTokens = []string{
	"acme-prod-a", "acme-prod-b", "acme-billing-exports", "123456789012", "AdminRole",
	"alice", "contoso", "i-0abc123", "54.12.33.9",
	"deploy@acme-prod-a.iam.gserviceaccount.com", "deploy@acme-prod-b.iam.gserviceaccount.com",
	"bob@contoso.onmicrosoft.com", "11111111-1111-1111-1111-111111111111",
	"22222222-2222-2222-2222-222222222222", "CC-7788",
}

func fixture() map[string][]byte {
	nodes := []map[string]any{
		{"node_id": "gcp|acme-prod-a|gcp:iam:service-account|deploy@acme-prod-a.iam.gserviceaccount.com",
			"node_type": "ServiceAccount", "provider": "gcp", "account": "acme-prod-a",
			"scope":      map[string]any{"provider": "gcp", "account": "acme-prod-a", "global": true},
			"attributes": map[string]any{"email": "deploy@acme-prod-a.iam.gserviceaccount.com", "displayName": "Deploy Robot"},
			"first_seen": "2026-08-01T10:00:00Z"},
		{"node_id": "gcp|acme-prod-b|gcp:iam:service-account|deploy@acme-prod-b.iam.gserviceaccount.com",
			"node_type": "ServiceAccount", "provider": "gcp", "account": "acme-prod-b",
			"scope":      map[string]any{"provider": "gcp", "account": "acme-prod-b", "global": true},
			"attributes": map[string]any{"email": "deploy@acme-prod-b.iam.gserviceaccount.com"}},
		{"node_id": "gcp|acme-prod-a|gcp:storage:bucket|acme-billing-exports",
			"node_type": "Bucket", "provider": "gcp", "account": "acme-prod-a",
			"attributes": map[string]any{"name": "acme-billing-exports", "location": "us-east1"}},
		{"node_id": "aws|123456789012|aws:iam:role|AdminRole", "node_type": "Role", "provider": "aws",
			"account": "123456789012", "arn": "arn:aws:iam::123456789012:role/AdminRole",
			"attributes": map[string]any{"tags": map[string]any{"Owner": "alice", "CostCenter": "CC-7788"}}},
		{"node_id": "aws|123456789012|aws:ec2:instance|i-0abc123", "node_type": "Instance", "provider": "aws",
			"account":    "123456789012",
			"attributes": map[string]any{"privateIp": "10.0.1.5", "subnet": "10.0.1.0/24", "publicIp": "54.12.33.9", "ingress": "0.0.0.0/0"}},
		{"node_id": "aws|123456789012|aws:ec2:instance|i-0def456", "node_type": "Instance", "provider": "aws",
			"account":    "123456789012",
			"attributes": map[string]any{"privateIp": "10.0.1.9", "subnet": "10.0.1.0/24"}},
		{"node_id": "azure|11111111-1111-1111-1111-111111111111|azure:aad:user|bob@contoso.onmicrosoft.com",
			"node_type": "HumanIdentity", "provider": "azure", "account": "11111111-1111-1111-1111-111111111111",
			"attributes": map[string]any{"userPrincipalName": "bob@contoso.onmicrosoft.com", "objectId": "22222222-2222-2222-2222-222222222222"}},
	}
	edges := []map[string]any{
		{"edge_id": "e1", "type": "gcp:impersonate", "provider": "gcp",
			"source": "gcp|acme-prod-a|gcp:iam:service-account|deploy@acme-prod-a.iam.gserviceaccount.com",
			"target": "gcp|acme-prod-b|gcp:iam:service-account|deploy@acme-prod-b.iam.gserviceaccount.com",
			"nature": "explicit", "state": "ACTIVE", "permissions": []any{"iam.serviceAccounts.getAccessToken"},
			"narrative":  "deploy@acme-prod-a.iam.gserviceaccount.com can impersonate deploy@acme-prod-b.iam.gserviceaccount.com",
			"evidence":   map[string]any{"role": "roles/owner", "bucket": "acme-billing-exports"},
			"first_seen": "2026-08-02T12:00:00Z"},
		{"edge_id": "e2", "type": "aws:can-assume", "provider": "aws",
			"source": "aws|123456789012|aws:iam:role|AdminRole",
			"target": "aws|123456789012|aws:ec2:instance|i-0abc123",
			"nature": "explicit", "state": "ACTIVE",
			"evidence": map[string]any{"arn": "arn:aws:iam::123456789012:role/AdminRole", "ip": "10.0.1.5"}},
	}
	paths := []map[string]any{
		{"path_id": "p1", "source": "gcp|acme-prod-a|gcp:iam:service-account|deploy@acme-prod-a.iam.gserviceaccount.com",
			"target":   "gcp|acme-prod-b|gcp:iam:service-account|deploy@acme-prod-b.iam.gserviceaccount.com",
			"edge_ids": []any{"e1"}, "score": 9.5,
			"narrative": "deploy@acme-prod-a.iam.gserviceaccount.com reaches deploy@acme-prod-b.iam.gserviceaccount.com"},
	}
	hits := []map[string]any{
		{"site_id": "s1", "resource_id": "gcp|acme-prod-a|gcp:storage:bucket|acme-billing-exports",
			"provider": "gcp", "location": "objectAcl", "value_ref": "salted-hash-deadbeef",
			"emits_hint": "gcp.storage.signedUrl", "severity": "high", "found": true},
	}
	eng := map[string]any{"provider": "multi", "account": "multi",
		"caller_arn": "deploy@acme-prod-a.iam.gserviceaccount.com", "created_at": "2026-08-03T09:00:00Z",
		"scopes": []any{
			map[string]any{"provider": "gcp", "ident": "acme-prod-a", "account": "acme-prod-a", "caller_arn": "deploy@acme-prod-a.iam.gserviceaccount.com"},
			map[string]any{"provider": "gcp", "ident": "acme-prod-b", "account": "acme-prod-b"},
			map[string]any{"provider": "aws", "ident": "prod", "account": "123456789012"},
			map[string]any{"provider": "azure", "ident": "sub-1", "account": "11111111-1111-1111-1111-111111111111"},
		}}

	files := map[string][]byte{
		"graph/nodes.ndjson":       ndjson(nodes),
		"graph/edges.ndjson":       ndjson(edges),
		"graph/paths.ndjson":       ndjson(paths),
		"exposure/hits.ndjson":     ndjson(hits),
		"exposure/surfaces.ndjson": []byte(""),
		"blobs/userdata-i-0abc123": []byte("#!/bin/bash\nexport BUCKET=acme-billing-exports\n# owner alice, acct 123456789012\n"),
	}
	eb, _ := json.MarshalIndent(eng, "", "  ")
	files["engagement.json"] = append(eb, '\n')
	return files
}

func ndjson(recs []map[string]any) []byte {
	var b strings.Builder
	for _, r := range recs {
		j, _ := json.Marshal(r)
		b.Write(j)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func runFixture(t *testing.T) (*AuditReport, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "real.zip")
	out := filepath.Join(dir, "anon.zip")
	if err := writeZip(in, fixture()); err != nil {
		t.Fatal(err)
	}
	report, err := Run(in, out, Options{})
	if err != nil {
		t.Fatalf("Run failed: %v (leaks=%v iso=%v)", err, report.LeakHits, report.Isomorphism)
	}
	got, err := readZip(out)
	if err != nil {
		t.Fatal(err)
	}
	return report, got
}

func TestRedact_AuditPasses(t *testing.T) {
	report, _ := runFixture(t)
	if !report.Pass {
		t.Fatalf("audit did not pass: leaks=%v iso=%v", report.LeakHits, report.Isomorphism)
	}
	if len(report.LeakHits) != 0 {
		t.Errorf("leak hits: %v", report.LeakHits)
	}
	if len(report.Isomorphism) != 0 {
		t.Errorf("isomorphism errors: %v", report.Isomorphism)
	}
}

func TestRedact_NoRealTokenSurvives(t *testing.T) {
	_, out := runFixture(t)
	for name, b := range out {
		text := string(b)
		for _, tok := range realTokens {
			if strings.Contains(text, tok) {
				t.Errorf("real token %q survived in %s", tok, name)
			}
		}
	}
}

func TestRedact_StructurePreserved(t *testing.T) {
	_, out := runFixture(t)
	if n := len(splitNDJSON(out["graph/nodes.ndjson"])); n != 7 {
		t.Errorf("nodes: got %d want 7", n)
	}
	if n := len(splitNDJSON(out["graph/edges.ndjson"])); n != 2 {
		t.Errorf("edges: got %d want 2", n)
	}
	if n := len(splitNDJSON(out["graph/paths.ndjson"])); n != 1 {
		t.Errorf("paths: got %d want 1", n)
	}
	// permissions kept verbatim (structural vocabulary)
	if !strings.Contains(string(out["graph/edges.ndjson"]), "iam.serviceAccounts.getAccessToken") {
		t.Error("permission action was altered (should be structural)")
	}
	// predefined role kept
	if !strings.Contains(string(out["graph/edges.ndjson"]), "roles/owner") {
		t.Error("predefined role roles/owner should be kept")
	}
	// "any" ingress kept
	if !strings.Contains(string(out["graph/nodes.ndjson"]), "0.0.0.0/0") {
		t.Error("0.0.0.0/0 should be preserved verbatim")
	}
}

func TestRedact_IdentityBoundary(t *testing.T) {
	_, out := runFixture(t)
	// The two same-named SAs in different projects must map to DIFFERENT fakes.
	var saA, saB string
	for _, line := range splitNDJSON(out["graph/nodes.ndjson"]) {
		m := parseObject(line)
		id := str(m["node_id"])
		if strings.Contains(id, "service-account") {
			if strings.HasPrefix(id, "gcp|") && str(m["node_type"]) == "ServiceAccount" {
				if saA == "" {
					saA = id
				} else {
					saB = id
				}
			}
		}
	}
	if saA == "" || saB == "" || saA == saB {
		t.Errorf("expected two distinct SA node ids, got %q and %q", saA, saB)
	}
	// different project segments
	pa, pb := strings.Split(saA, "|")[1], strings.Split(saB, "|")[1]
	if pa == pb {
		t.Errorf("same-named SAs collapsed into one project realm: %q", pa)
	}
}

func TestRedact_NetworkTopologyPreserved(t *testing.T) {
	_, out := runFixture(t)
	// The two instances share subnet 10.0.1.0/24; their fake private IPs must share a /24.
	var ips []string
	for _, line := range splitNDJSON(out["graph/nodes.ndjson"]) {
		m := parseObject(line)
		attrs, _ := m["attributes"].(map[string]any)
		if attrs == nil {
			continue
		}
		if ip, ok := attrs["privateIp"].(string); ok {
			ips = append(ips, ip)
		}
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 private IPs, got %v", ips)
	}
	pre := func(s string) string { return s[:strings.LastIndex(s, ".")] }
	if pre(ips[0]) != pre(ips[1]) {
		t.Errorf("same-subnet IPs no longer share a /24: %v", ips)
	}
	for _, ip := range ips {
		if strings.HasPrefix(ip, "54.") { // original public octet must not survive
			t.Errorf("real-ish IP leaked: %s", ip)
		}
	}
}

func TestRedact_Deterministic(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	one := transformWith(salt)
	two := transformWith(salt)
	if one != two {
		t.Error("same salt should yield identical fakes")
	}
}

func transformWith(salt []byte) string {
	r := newRegistryWithSalt(salt)
	tr := newTransformer(r)
	r.Prepare()
	return tr.remapNodeID("gcp|acme-prod-a|gcp:iam:service-account|deploy@acme-prod-a.iam.gserviceaccount.com")
}
