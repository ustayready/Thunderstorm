package evaluator

import (
	"strings"
	"testing"

	"thunderstorm/engine/internal/model"
)

// serviceMatches must stop cross-service false positives: a dynamodb action must
// not apply to a Keyspaces resource just because both are NoSQLDatabase.
func TestServiceMatchesGuardsCrossService(t *testing.T) {
	dynamo := model.Node{NodeID: "aws|1|aws:dynamodb:table|orders", ARN: "arn:aws:dynamodb:us-east-1:1:table/orders"}
	keyspace := model.Node{NodeID: "aws|1|aws:keyspaces:keyspace|system_schema_mcs"}
	if !serviceMatches("dynamodb:GetItem", dynamo) {
		t.Errorf("dynamodb:GetItem should apply to a dynamodb table")
	}
	if serviceMatches("dynamodb:GetItem", keyspace) {
		t.Errorf("dynamodb:GetItem must NOT apply to a keyspaces resource")
	}
	// SSM command targets EC2 instances (cross-service override).
	ec2 := model.Node{NodeID: "aws|1|aws:ec2:instance|i-abc"}
	if !serviceMatches("ssm:SendCommand", ec2) {
		t.Errorf("ssm:SendCommand should apply to an ec2 instance")
	}
	// SSM parameter store resource_type is aws:ssm-params.
	param := model.Node{NodeID: "aws|1|aws:ssm-params:parameter|/db/pw"}
	if !serviceMatches("ssm:GetParameter", param) {
		t.Errorf("ssm:GetParameter should apply to an ssm-params resource")
	}
}

// The capability table is the growth surface of the evaluator; a malformed row
// silently drops an edge type. Assert every row is well-formed. This is the
// evaluator half of the rule-spec drift guard.
func TestCapabilityTableWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range capabilities {
		if c.Edge == "" {
			t.Errorf("capability with empty Edge: %+v", c)
		}
		if !strings.Contains(c.Action, ":") {
			t.Errorf("%s: action %q is not a service:action", c.Edge, c.Action)
		}
		if len(c.TargetNodeTypes) == 0 {
			t.Errorf("%s: no target node types", c.Edge)
		}
		if c.Weight <= 0 {
			t.Errorf("%s: weight must be positive, got %v", c.Edge, c.Weight)
		}
		key := c.Edge + "|" + c.Action
		if seen[key] {
			t.Errorf("duplicate capability row %s", key)
		}
		seen[key] = true
	}
}
