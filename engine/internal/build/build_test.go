package build

import (
	"testing"
	"time"

	"thunderstorm/engine/internal/model"
)

func findEdge(edges []model.Edge, typ, srcSub, tgtSub string) *model.Edge {
	for i := range edges {
		e := edges[i]
		if e.Type == typ && contains(e.Source, srcSub) && contains(e.Target, tgtSub) {
			return &edges[i]
		}
	}
	return nil
}

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// A public S3 bucket policy (Principal:"*") must produce a CrossAccountTrust edge
// to the Everyone node. This is the M4a golden expectation.
func TestPublicResourcePolicyProducesCrossAccountTrust(t *testing.T) {
	facts := []model.Fact{{
		Kind:     "resource_policy",
		EdgeHint: "CrossAccountTrust",
		Provider: "aws",
		Scope:    model.Scope{Provider: "aws", Account: "111122223333", Region: "us-east-1"},
		Source:   "arn:aws:s3:::example-public",
		Attributes: map[string]any{
			"policy": `{"Version":"2012-10-17","Statement":[{"Sid":"pub","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::example-public/*"}]}`,
		},
	}}
	res := Build(nil, facts, time.Now())
	e := findEdge(res.Graph.Edges, "CrossAccountTrust", "example-public", "principal:*")
	if e == nil {
		t.Fatalf("expected CrossAccountTrust edge to Everyone; edges=%+v", res.Graph.Edges)
	}
	if e.State != model.StateActive {
		t.Errorf("public edge state = %q, want ACTIVE", e.State)
	}
	if len(e.Permissions) == 0 || e.Permissions[0] != "s3:GetObject" {
		t.Errorf("permissions = %v, want [s3:GetObject]", e.Permissions)
	}
}

// A cross-account trust policy must produce CanAssume(principal -> role); a
// same-account resource-policy grant must NOT be flagged cross-account.
func TestTrustAndSameAccountHandling(t *testing.T) {
	facts := []model.Fact{
		{
			Kind: "trust_policy", EdgeHint: "CanAssume", Provider: "aws",
			Scope:  model.Scope{Provider: "aws", Account: "111122223333"},
			Source: "arn:aws:iam::111122223333:role/target",
			Attributes: map[string]any{
				"document": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Kind: "resource_policy", EdgeHint: "CrossAccountTrust", Provider: "aws",
			Scope:  model.Scope{Provider: "aws", Account: "111122223333", Region: "us-east-1"},
			Source: "arn:aws:sns:us-east-1:111122223333:topic",
			Attributes: map[string]any{
				"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sns:Publish","Resource":"*"}]}`,
			},
		},
	}
	res := Build(nil, facts, time.Now())
	if e := findEdge(res.Graph.Edges, "CanAssume", "999988887777", "role/target"); e == nil {
		t.Errorf("expected cross-account CanAssume edge")
	}
	// same-account SNS grant should not become CrossAccountTrust
	if e := findEdge(res.Graph.Edges, "CrossAccountTrust", "topic", "111122223333"); e != nil {
		t.Errorf("same-account grant wrongly flagged CrossAccountTrust: %+v", e)
	}
}

// ExecutesAs must be emitted from an inventory role attribute.
func TestExecutesAsFromRoleAttr(t *testing.T) {
	arts := []model.Artifact{{
		Provider: "aws", Account: "111122223333",
		ResourceType: "aws:lambda:function", NodeType: "ServerlessFunction",
		NativeID:   "fn",
		Attributes: map[string]any{"role_arn": "arn:aws:iam::111122223333:role/exec"},
	}}
	res := Build(arts, nil, time.Now())
	if e := findEdge(res.Graph.Edges, "ExecutesAs", "fn", "role/exec"); e == nil {
		t.Errorf("expected ExecutesAs edge from role_arn attribute")
	}
}
