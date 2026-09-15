package evaluator

import (
	"strings"
	"time"

	"thunderstorm/engine/internal/model"
)

// actionServiceOverride maps an action to the resource SERVICE(s) it targets when
// they differ from the action's own service prefix. SSM commands target EC2
// instances; SSM parameters live under the ssm-params resource_type.
var actionServiceOverride = map[string][]string{
	"ssm:GetParameter": {"ssm-params"},
	"ssm:SendCommand":  {"ec2"},
	"ssm:StartSession": {"ec2"},
}

// allowedServices returns the resource services an action legitimately applies to.
func allowedServices(action string) []string {
	if o, ok := actionServiceOverride[action]; ok {
		return o
	}
	if i := strings.Index(action, ":"); i > 0 {
		return []string{action[:i]}
	}
	return nil
}

// serviceOfResource derives a node's AWS service from its node_id resource_type
// (aws|acct|aws:dynamodb:table|name -> "dynamodb"), falling back to its ARN.
func serviceOfResource(n model.Node) string {
	parts := strings.Split(n.NodeID, "|")
	if len(parts) >= 3 {
		seg := strings.Split(parts[2], ":") // e.g. aws:keyspaces:keyspace
		if len(seg) >= 2 {
			return seg[1]
		}
	}
	if a := strings.Split(n.ARN, ":"); len(a) >= 3 {
		return a[2]
	}
	return ""
}

// serviceMatches guards against cross-service false positives: a capability's
// action must apply to the resource's actual service (e.g. dynamodb:GetItem must
// not match a Keyspaces resource just because both are NoSQLDatabase).
func serviceMatches(action string, res model.Node) bool {
	want := serviceOfResource(res)
	for _, s := range allowedServices(action) {
		if s == want {
			return true
		}
	}
	return false
}

// Capability maps a graph edge type to the IAM action whose effective allow
// creates it, and the resource node types it applies to. This is the rule-driven
// (targeted) principal-set scope — we only evaluate the
// (identity, resource) pairs a capability actually targets, not every pair.
type Capability struct {
	Edge            string
	Action          string
	TargetNodeTypes []string
	RelKind         string
	Weight          float64
	Narrative       string // "<p> <verb> <r>"
	// ResourceSuffix is appended to the resource ARN before evaluation. Object-
	// level S3 actions (GetObject/PutObject) authorize on the object namespace
	// "<bucket>/*", not the bucket ARN, so they set "/*".
	ResourceSuffix string
}

// capabilities maps every permission-derived edge type in RAGE vocab/edge-types.json
// that has a concrete AWS action trigger to (action, target node types). Extending the
// engine's breadth = adding rows here. Node types come from RAGE vocab/node-types.json
// classes. Identity-target capabilities (privesc surface) target the
// identity node classes; the derivation engine (derive/) composes these into
// CanEscalateTo / CanImpersonate chains.
var capabilities = []Capability{
	// --- credential access (CREDENTIAL) ---
	{"CanReadSecret", "secretsmanager:GetSecretValue", []string{"Secret"}, "CREDENTIAL", 1.0, "can read secret", ""},
	{"CanReadSecret", "ssm:GetParameter", []string{"Secret"}, "CREDENTIAL", 1.0, "can read parameter", ""},
	{"CanDecrypt", "kms:Decrypt", []string{"EncryptionKey"}, "CREDENTIAL", 1.0, "can decrypt with", ""},
	// NOTE: KMS has no "export CMK key material" API — kms:GetPublicKey returns only
	// the PUBLIC half of an asymmetric key, which is not a credential exposure. So
	// CanExportKey is intentionally NOT mapped to a KMS action (would be a false edge).
	{"CanReadData", "s3:GetObject", []string{"ObjectStorage"}, "CREDENTIAL", 2.0, "can read data in", "/*"},
	{"CanReadData", "dynamodb:GetItem", []string{"NoSQLDatabase"}, "CREDENTIAL", 2.0, "can read data in", ""},

	// --- execution (EXECUTION) ---
	{"CanInvoke", "lambda:InvokeFunction", []string{"ServerlessFunction"}, "EXECUTION", 1.0, "can invoke", ""},
	{"CanModifyCode", "lambda:UpdateFunctionCode", []string{"ServerlessFunction"}, "EXECUTION", 1.0, "can modify code of", ""},
	{"CanModifyCode", "ecr:PutImage", []string{"ContainerRegistry"}, "EXECUTION", 1.0, "can push image to", ""},
	{"CanModifyConfiguration", "lambda:UpdateFunctionConfiguration", []string{"ServerlessFunction"}, "EXECUTION", 1.0, "can modify configuration of", ""},
	{"CanExecuteCommand", "ssm:SendCommand", []string{"VirtualMachine", "GenericCompute"}, "EXECUTION", 1.0, "can run commands on", ""},
	{"CanExecuteCommand", "ssm:StartSession", []string{"VirtualMachine", "GenericCompute"}, "EXECUTION", 1.0, "can open a session on", ""},
	{"CanWriteData", "s3:PutObject", []string{"ObjectStorage"}, "EXECUTION", 2.0, "can write data in", "/*"},
	{"CanTrigger", "sns:Publish", []string{"Topic"}, "EXECUTION", 2.0, "can publish to", ""},
	{"CanTrigger", "sqs:SendMessage", []string{"Queue"}, "EXECUTION", 2.0, "can enqueue to", ""},
	{"CanStart", "ec2:StartInstances", []string{"VirtualMachine"}, "EXECUTION", 2.0, "can start", ""},

	// --- authorization / identity control (AUTHORIZATION) — privesc surface ---
	{"CanPassIdentity", "iam:PassRole", []string{"Role"}, "AUTHORIZATION", 1.0, "can pass", ""},
	{"CanAddMember", "iam:AddUserToGroup", []string{"Group"}, "AUTHORIZATION", 1.0, "can add members to", ""},
	{"CanModifyTrust", "iam:UpdateAssumeRolePolicy", []string{"Role"}, "AUTHORIZATION", 1.0, "can modify the trust policy of", ""},
	{"CanCreateCredentialFor", "iam:CreateAccessKey", []string{"HumanIdentity"}, "CREDENTIAL", 1.0, "can create access keys for", ""},
	{"CanResetCredential", "iam:UpdateLoginProfile", []string{"HumanIdentity"}, "CREDENTIAL", 1.0, "can reset the console password of", ""},

	// --- resource control (CONTROL) ---
	{"CanModifyPolicy", "iam:PutRolePolicy", []string{"Role"}, "CONTROL", 1.0, "can attach an inline policy to", ""},
	{"CanModifyPolicy", "iam:PutUserPolicy", []string{"HumanIdentity"}, "CONTROL", 1.0, "can attach an inline policy to", ""},
	{"CanModify", "s3:PutBucketPolicy", []string{"ObjectStorage"}, "CONTROL", 2.0, "can rewrite the resource policy of", ""},
	{"CanModify", "kms:PutKeyPolicy", []string{"EncryptionKey"}, "CONTROL", 2.0, "can rewrite the key policy of", ""},
	{"CanModify", "lambda:AddPermission", []string{"ServerlessFunction"}, "CONTROL", 2.0, "can add a resource-policy grant to", ""},
	{"CanDelete", "dynamodb:DeleteTable", []string{"NoSQLDatabase"}, "CONTROL", 3.0, "can delete", ""},
}

// identityNodeTypes are the node types treated as principals to evaluate from.
var identityNodeTypes = map[string]bool{
	"HumanIdentity": true, "Role": true, "ServiceIdentity": true,
	"FederatedIdentity": true, "ApplicationIdentity": true,
}

// EvaluatePermissions runs the capability table over the graph's principals and
// resources, returning the permission-derived edges. Only ACTIVE or CONDITIONAL
// allows produce edges.
func EvaluatePermissions(store *Store, nodes []model.Node, at time.Time) []model.Edge {
	var principals, resources []model.Node
	for _, n := range nodes {
		if n.ARN == "" {
			continue
		}
		if identityNodeTypes[n.NodeType] {
			principals = append(principals, n)
		}
		resources = append(resources, n)
	}

	byType := map[string][]model.Node{}
	for _, r := range resources {
		byType[r.NodeType] = append(byType[r.NodeType], r)
	}

	var edges []model.Edge
	for _, cap := range capabilities {
		var targets []model.Node
		for _, nt := range cap.TargetNodeTypes {
			targets = append(targets, byType[nt]...)
		}
		for _, res := range targets {
			if !serviceMatches(cap.Action, res) {
				continue // action's service must match the resource's service
			}
			for _, p := range principals {
				if p.NodeID == res.NodeID {
					continue
				}
				dec := store.Evaluate(p.ARN, cap.Action, res.ARN+cap.ResourceSuffix)
				if !dec.Allowed {
					continue
				}
				state := model.StateActive
				conf := 1.0
				if dec.Conditional {
					state = model.StateConditional
					conf = 0.5
				}
				edges = append(edges, model.Edge{
					EdgeID: model.EdgeID(cap.Edge, p.NodeID, res.NodeID, res.ARN),
					Type:   cap.Edge, Source: p.NodeID, Target: res.NodeID,
					RelationshipKind: cap.RelKind, Nature: model.NatureExplicit,
					Provider: p.Provider, State: state, Confidence: conf, Weight: cap.Weight,
					Scope: res.ARN, Permissions: []string{cap.Action}, Conditions: dec.Conditions,
					Facts:     dec.Facts, // provenance: the policy facts that produced this allow
					Evidence:  map[string]any{"via": dec.Via, "action": cap.Action},
					Narrative: shortLabel(p) + " " + cap.Narrative + " " + shortLabel(res),
					FirstSeen: at,
				})
			}
		}
	}
	return edges
}

func shortLabel(n model.Node) string {
	s := n.ARN
	if s == "" {
		s = n.NodeID
	}
	for _, sep := range []string{"/", ":"} {
		if i := lastIndex(s, sep); i >= 0 {
			s = s[i+1:]
		}
	}
	return s
}

func lastIndex(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// EmittedEdgeTypes returns the distinct edge types the capability table produces.
// Used by the conformance test to guard against drift from RAGE vocab/edge-types.json.
func EmittedEdgeTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range capabilities {
		if !seen[c.Edge] {
			seen[c.Edge] = true
			out = append(out, c.Edge)
		}
	}
	return out
}

// TargetNodeTypes returns the distinct resource node types the capabilities target.
func TargetNodeTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range capabilities {
		for _, nt := range c.TargetNodeTypes {
			if !seen[nt] {
				seen[nt] = true
				out = append(out, nt)
			}
		}
	}
	return out
}
