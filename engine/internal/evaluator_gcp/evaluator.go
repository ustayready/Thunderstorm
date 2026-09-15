// Package evaluator_gcp is the GCP effective-permission evaluator. GCP IAM is
// binding-based (member + role + condition) with hierarchy inheritance, not AWS's
// statement/principal model — so it needs its own evaluator. It consumes the
// collector's iam_binding + role_permissions facts and emits capability edges:
//
//	member has role R on resource X (or project-wide) ; R includes permission P ;
//	P maps to edge E over node class C  =>  edge (member -> X) of type E.
//
// Project-level bindings inherit to EVERY resource (GCP's automatic downward
// inheritance); resource-level bindings apply to that resource only. A binding
// with an (unresolved) CEL condition yields a CONDITIONAL edge, mirroring AWS.
package evaluator_gcp

import (
	"strings"
	"time"

	"thunderstorm/engine/internal/model"
)

// gcpCapability maps a GCP permission to the edge it creates and the node classes
// it targets. Node classes match RAGE vocab/node-types.json classes.
type gcpCapability struct {
	edge    string
	perm    string
	targets []string
	relKind string
	weight  float64
	verb    string
}

var capabilities = []gcpCapability{
	// credential / data access
	{"CanReadSecret", "secretmanager.versions.access", []string{"Secret"}, "CREDENTIAL", 1.0, "can read secret"},
	{"CanReadData", "storage.objects.get", []string{"ObjectStorage"}, "CREDENTIAL", 2.0, "can read data in"},
	{"CanWriteData", "storage.objects.create", []string{"ObjectStorage"}, "EXECUTION", 2.0, "can write data in"},
	{"CanReadData", "bigquery.tables.getData", []string{"DataWarehouse", "NoSQLDatabase"}, "CREDENTIAL", 2.0, "can read data in"},
	{"CanDecrypt", "cloudkms.cryptoKeyVersions.useToDecrypt", []string{"EncryptionKey"}, "CREDENTIAL", 1.0, "can decrypt with"},
	// service-account impersonation (the GCP privesc backbone)
	{"CanImpersonate", "iam.serviceAccounts.getAccessToken", []string{"ServiceAccount"}, "AUTHORIZATION", 1.0, "can impersonate"},
	{"CanImpersonate", "iam.serviceAccounts.getOpenIdToken", []string{"ServiceAccount"}, "AUTHORIZATION", 1.0, "can impersonate"},
	{"CanImpersonate", "iam.serviceAccounts.implicitDelegation", []string{"ServiceAccount"}, "AUTHORIZATION", 1.0, "can impersonate"},
	{"CanSignAs", "iam.serviceAccounts.signBlob", []string{"ServiceAccount"}, "AUTHORIZATION", 1.0, "can sign as"},
	{"CanSignAs", "iam.serviceAccounts.signJwt", []string{"ServiceAccount"}, "AUTHORIZATION", 1.0, "can sign JWTs as"},
	{"CanPassIdentity", "iam.serviceAccounts.actAs", []string{"ServiceAccount"}, "AUTHORIZATION", 1.0, "can attach"},
	{"CanCreateCredentialFor", "iam.serviceAccountKeys.create", []string{"ServiceAccount"}, "CREDENTIAL", 1.0, "can create keys for"},
	// execution
	{"CanInvoke", "cloudfunctions.functions.call", []string{"ServerlessFunction"}, "EXECUTION", 1.0, "can invoke"},
	{"CanModifyCode", "cloudfunctions.functions.update", []string{"ServerlessFunction"}, "EXECUTION", 1.0, "can modify code of"},
	{"CanInvoke", "run.routes.invoke", []string{"ContainerService"}, "EXECUTION", 1.0, "can invoke"},
	{"CanModifyCode", "run.services.update", []string{"ContainerService"}, "EXECUTION", 1.5, "can modify"},
	{"CanExecuteCommand", "compute.instances.setMetadata", []string{"VirtualMachine"}, "EXECUTION", 2.0, "can run commands on"},
	{"CanStart", "compute.instances.start", []string{"VirtualMachine"}, "EXECUTION", 2.0, "can start"},
	{"CanModifyCode", "artifactregistry.repositories.uploadArtifacts", []string{"ContainerRegistry"}, "EXECUTION", 2.0, "can push images to"},
	{"CanInvoke", "cloudfunctions.functions.invoke", []string{"ServerlessFunction"}, "EXECUTION", 1.0, "can invoke"},
	{"CanTrigger", "pubsub.topics.publish", []string{"Topic"}, "EXECUTION", 2.0, "can publish to"},
	// deploy/run/build/job AS the service's identity (privesc via a compute pivot)
	{"CanPassIdentity", "compute.instances.setServiceAccount", []string{"VirtualMachine"}, "AUTHORIZATION", 2.0, "can rebind the service account of"},
	{"CanExecuteCommand", "compute.instances.osAdminLogin", []string{"VirtualMachine"}, "EXECUTION", 2.0, "can SSH as admin to"},
	{"CanExecuteCommand", "compute.projects.setCommonInstanceMetadata", []string{"VirtualMachine"}, "EXECUTION", 2.0, "can add project SSH keys affecting"},
	{"CanModifyCode", "deploymentmanager.deployments.update", []string{"AutomationService"}, "EXECUTION", 2.0, "can deploy resources via"},
	{"CanModifyCode", "deploymentmanager.deployments.create", []string{"AutomationService"}, "EXECUTION", 2.0, "can deploy resources via"},
	{"CanModifyCode", "appengine.versions.create", []string{"ApplicationPlatform"}, "EXECUTION", 2.0, "can deploy a version to"},
	{"CanExecuteCommand", "cloudbuild.builds.create", []string{"BuildWorker"}, "EXECUTION", 2.0, "can run build steps as"},
	{"CanExecuteCommand", "dataproc.jobs.create", []string{"AnalyticsService"}, "EXECUTION", 2.0, "can submit jobs to"},
	{"CanExecuteCommand", "composer.environments.executeAirflowCommand", []string{"Workflow"}, "EXECUTION", 2.0, "can run Airflow commands in"},
	{"CanModifyCode", "dataflow.jobs.updateContents", []string{"AnalyticsService"}, "EXECUTION", 1.5, "can modify job of"},
	{"CanModifyCode", "workflows.workflows.update", []string{"Workflow"}, "EXECUTION", 1.5, "can modify definition of"},
	{"CanTrigger", "cloudscheduler.jobs.create", []string{"Scheduler"}, "EXECUTION", 1.5, "can schedule invocations via"},
	{"CanTrigger", "eventarc.triggers.create", []string{"EventBus"}, "EXECUTION", 1.0, "can create triggers on"},
	// durable credentials
	{"CanSignAs", "cloudkms.cryptoKeyVersions.useToSign", []string{"EncryptionKey"}, "AUTHORIZATION", 1.0, "can sign with"},
	{"CanCreateCredentialFor", "storage.hmacKeys.create", []string{"ServiceAccount"}, "CREDENTIAL", 1.0, "can create HMAC keys for"},
	{"CanModifyPolicy", "iam.roles.update", []string{"Role"}, "CONTROL", 2.0, "can add permissions to custom role"},
	// control / escalation — setIamPolicy on the resource is self-grant (-> CanControl)
	{"CanGrantPermission", "resourcemanager.projects.setIamPolicy", []string{"Project"}, "CONTROL", 2.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "iam.serviceAccounts.setIamPolicy", []string{"ServiceAccount"}, "CONTROL", 1.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "storage.buckets.setIamPolicy", []string{"ObjectStorage"}, "CONTROL", 2.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "cloudkms.cryptoKeys.setIamPolicy", []string{"EncryptionKey"}, "CONTROL", 1.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "secretmanager.secrets.setIamPolicy", []string{"Secret"}, "CONTROL", 1.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "run.services.setIamPolicy", []string{"ContainerService"}, "CONTROL", 1.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "cloudfunctions.functions.setIamPolicy", []string{"ServerlessFunction"}, "CONTROL", 1.0, "can rewrite the IAM policy of"},
	{"CanModifyPolicy", "pubsub.topics.setIamPolicy", []string{"Topic"}, "CONTROL", 1.0, "can rewrite the IAM policy of"},
}

// identityNodeTypes are node classes that represent principals a member resolves to.
var identityNodeTypes = map[string]bool{
	"ServiceAccount": true, "HumanIdentity": true, "Group": true,
	"FederatedIdentity": true, "Everyone": true, "Role": true,
}

type grant struct {
	perms     map[string]bool
	anyCond   bool     // some binding granting this had a condition
	anyUncond bool     // some binding granting this was unconditional
	facts     []string // fact_ids of the iam_binding facts that produced this grant (provenance)
}

// pgKey identifies a project-wide grant by (member, project). Keying by project is
// essential once bundles are MERGED across projects: a project-wide role only covers
// its OWN project's resources, so without the project a broad grant would fan out to
// every matching resource in every project — a cross-product edge explosion (and false
// cross-project edges).
type pgKey struct {
	member, account string
}

// conditional: the grant is only usable under a condition iff EVERY binding that
// produced it was conditioned (any unconditional binding makes it solid).
func (g *grant) conditional() bool { return g.anyCond && !g.anyUncond }

// EvaluatePermissions turns iam_binding + role_permissions facts into capability
// edges, synthesizing identity nodes for members not present in inventory
// (users/groups/allUsers/WIF). Returns (edges, synthesizedNodes).
func EvaluatePermissions(facts []model.Fact, nodes []model.Node, at time.Time) ([]model.Edge, []model.Node) {
	project := ""
	if len(nodes) > 0 {
		project = nodes[0].Account
	}

	// role -> permission set
	roleToPerms := map[string]map[string]bool{}
	for _, f := range facts {
		if f.Kind != "role_permissions" {
			continue
		}
		set := map[string]bool{}
		for _, p := range toStrings(f.Attributes["permissions"]) {
			set[p] = true
		}
		roleToPerms[f.Source] = set
	}

	// member -> project-wide grant (keyed by member+project), and member -> resource -> grant
	projectGrant := map[pgKey]*grant{}
	resourceGrant := map[string]map[string]*grant{}
	for _, f := range facts {
		if f.Kind != "iam_binding" {
			continue
		}
		role, _ := f.Attributes["role"].(string)
		perms := roleToPerms[role]
		if len(perms) == 0 {
			continue
		}
		cond := f.Attributes["condition"] != nil && f.Attributes["condition"] != ""
		level, _ := f.Attributes["level"].(string)
		if level == "project" {
			key := pgKey{member: f.Source, account: f.Scope.Account}
			g := projectGrant[key]
			if g == nil {
				g = &grant{perms: map[string]bool{}}
				projectGrant[key] = g
			}
			mergePerms(g, perms, cond, model.FactID(f))
		} else {
			byRes := resourceGrant[f.Source]
			if byRes == nil {
				byRes = map[string]*grant{}
				resourceGrant[f.Source] = byRes
			}
			g := byRes[f.Target]
			if g == nil {
				g = &grant{perms: map[string]bool{}}
				byRes[f.Target] = g
			}
			mergePerms(g, perms, cond, model.FactID(f))
		}
	}

	// resource node index: by ARN, native id, and last path segment
	byName := map[string]*model.Node{}
	byType := map[string][]*model.Node{}
	for i := range nodes {
		n := &nodes[i]
		if n.ARN != "" {
			byName[n.ARN] = n
			byName[lastSeg(n.ARN)] = n
		}
		if nid := nativeOf(n); nid != "" {
			byName[nid] = n
			byName[lastSeg(nid)] = n
		}
		byType[n.NodeType] = append(byType[n.NodeType], n)
	}

	synth := map[string]*model.Node{} // synthesized identity nodes (member -> node)
	resolveMember := func(member string) *model.Node {
		return resolveMemberNode(member, project, byName, synth)
	}

	var edges []model.Edge
	emitted := map[string]int{} // edge id -> index in edges
	emit := func(cap gcpCapability, src *model.Node, res *model.Node, conditional bool, facts []string) {
		if src == nil || res == nil || src.NodeID == res.NodeID {
			return
		}
		id := model.EdgeID(cap.edge, src.NodeID, res.NodeID, res.ARN)
		if idx, ok := emitted[id]; ok {
			// dedup, but never let a CONDITIONAL grant mask a later unconditional
			// one for the same (edge,src,res): an ACTIVE path must win.
			if !conditional && edges[idx].State == model.StateConditional {
				edges[idx].State = model.StateActive
				edges[idx].Confidence = 1.0
			}
			return
		}
		state := model.StateActive
		conf := 1.0
		if conditional {
			state = model.StateConditional
			conf = 0.5
		}
		emitted[id] = len(edges)
		edges = append(edges, model.Edge{
			EdgeID: id, Type: cap.edge, Source: src.NodeID, Target: res.NodeID,
			RelationshipKind: cap.relKind, Nature: model.NatureExplicit,
			Provider: "gcp", State: state, Confidence: conf, Weight: cap.weight,
			Scope: res.ARN, Permissions: []string{cap.perm},
			Facts:     facts, // provenance: the iam_binding facts behind this grant
			Evidence:  map[string]any{"via": "iam-binding", "permission": cap.perm},
			Narrative: shortName(src) + " " + cap.verb + " " + shortName(res),
			FirstSeen: at,
		})
	}

	for _, cap := range capabilities {
		var targets []*model.Node
		for _, t := range cap.targets {
			targets = append(targets, byType[t]...)
		}
		if len(targets) == 0 {
			continue
		}
		// project-wide grants: member has perm over every resource of the class IN THAT
		// grant's OWN project (res.Account == the grant's project) — not across projects.
		for key, g := range projectGrant {
			if !g.perms[cap.perm] || isGoogleManaged(key.member) {
				continue
			}
			src := resolveMember(key.member)
			for _, res := range targets {
				if res.Account != key.account {
					continue
				}
				emit(cap, src, res, g.conditional(), g.facts)
			}
		}
		// resource-scoped grants
		for member, byRes := range resourceGrant {
			if isGoogleManaged(member) {
				continue
			}
			for resName, g := range byRes {
				if !g.perms[cap.perm] {
					continue
				}
				res := byName[resName]
				if res == nil {
					res = byName[lastSeg(resName)]
				}
				if res == nil || !inTargets(res.NodeType, cap.targets) {
					continue
				}
				emit(cap, resolveMember(member), res, g.conditional(), g.facts)
			}
		}
	}

	// collect synthesized nodes
	extra := make([]model.Node, 0, len(synth))
	for _, n := range synth {
		extra = append(extra, *n)
	}
	return edges, extra
}

func mergePerms(g *grant, perms map[string]bool, cond bool, factID string) {
	for p := range perms {
		g.perms[p] = true
	}
	if cond {
		g.anyCond = true
	} else {
		g.anyUncond = true
	}
	if factID != "" {
		for _, x := range g.facts {
			if x == factID {
				return
			}
		}
		g.facts = append(g.facts, factID)
	}
}

// resolveMemberNode maps an IAM member string to a graph node (existing SA/identity
// or a synthesized one for users/groups/allUsers/WIF principals). Synthesized nodes are
// homed to the identity's REALM (see identityRealm), not the referencing project, so a
// user/group/SA granted in many projects is ONE node — not one arbitrary-project copy
// per binding, which across a multi-project graph would otherwise manufacture a storm of
// fake "cross-project" edges from every shared admin/group.
func resolveMemberNode(member, project string, byName map[string]*model.Node, synth map[string]*model.Node) *model.Node {
	if n, ok := synth[member]; ok {
		return n
	}
	kind, val, ok := splitMember(member)
	if !ok {
		return nil
	}
	realm := identityRealm(kind, val, project)
	switch kind {
	case "serviceAccount":
		if n := byName[val]; n != nil {
			return n
		}
		return synthNode(synth, member, realm, "gcp:iam:service-account", "ServiceAccount", val)
	case "user":
		return synthNode(synth, member, realm, "gcp:iam:user", "HumanIdentity", val)
	case "group":
		return synthNode(synth, member, realm, "gcp:iam:group", "Group", val)
	case "domain":
		// a whole Workspace domain — broad, but a bounded principal set; model as a
		// Group so the grant isn't silently dropped (blast-radius nuance is a follow-up).
		return synthNode(synth, member, realm, "gcp:iam:domain", "Group", val)
	case "principalSet", "principal":
		return synthNode(synth, member, realm, "gcp:iam:federated-identity", "FederatedIdentity", val)
	case "allUsers", "allAuthenticatedUsers":
		return synthNode(synth, member, realm, "gcp:iam:everyone", "Everyone", kind)
	default:
		return nil
	}
}

// identityRealm returns the account/home segment for a synthesized member node. The
// principle: home an identity where it LIVES, not where a grant to it was found.
//   - service account  -> its project (from the @PROJECT.iam email); default agents that
//     aren't project-homed -> "external".
//   - user / group     -> its email domain (e.g. "trustedsec.com") — a stable, project-
//     independent realm, so the same person/group is one node across all projects.
//   - domain           -> the domain itself.
//   - allUsers/allAuth  -> "public".
//   - federated (WIF)   -> "external".
//
// These realms are deliberately NOT collected-project ids, so the viz can treat an edge
// FROM such an identity into a project as "external access", not a project↔project pivot.
func identityRealm(kind, val, fallbackProject string) string {
	switch kind {
	case "serviceAccount":
		if i := strings.IndexByte(val, '@'); i >= 0 {
			dom := val[i+1:]
			if strings.HasSuffix(dom, ".iam.gserviceaccount.com") {
				return strings.TrimSuffix(dom, ".iam.gserviceaccount.com")
			}
			return "external" // NUM-compute@developer, @appspot, @cloudbuild — not project-homed
		}
		return fallbackProject
	case "user", "group":
		if i := strings.IndexByte(val, '@'); i >= 0 {
			return val[i+1:]
		}
		return "external"
	case "domain":
		return val
	case "allUsers", "allAuthenticatedUsers":
		return "public"
	default:
		return "external"
	}
}

// FootholdNode builds a graph node for the collector's own caller identity so it is
// ALWAYS present as the "you are here" anchor — even when that identity holds no
// project-scoped IAM binding (the common case for a human whose access to a project is
// inherited from an org/folder role or group membership, so it appears in zero project
// bindings). caller is the bare email returned by tokeninfo (SA or user); project is the
// scope it authenticated against. The node mirrors the member-node id/realm conventions
// so it DEDUPES with a binding-derived node when one exists. Returns nil for a caller
// that isn't an email (nothing to anchor to).
func FootholdNode(caller, project string) *model.Node {
	caller = strings.TrimSpace(caller)
	if caller == "" || !strings.Contains(caller, "@") {
		return nil
	}
	kind, rt, nt := "user", "gcp:iam:user", "HumanIdentity"
	if strings.HasSuffix(caller, "gserviceaccount.com") {
		kind, rt, nt = "serviceAccount", "gcp:iam:service-account", "ServiceAccount"
	}
	realm := identityRealm(kind, caller, project)
	return &model.Node{
		NodeID: "gcp|" + realm + "|" + rt + "|" + caller, NodeType: nt,
		Provider: "gcp", Account: realm, ARN: caller,
		Attributes: map[string]any{"synthesized": true, "member": kind + ":" + caller,
			"foothold": true, "collector_identity": true},
	}
}

func synthNode(synth map[string]*model.Node, member, realm, rt, nt, native string) *model.Node {
	n := &model.Node{
		NodeID: "gcp|" + realm + "|" + rt + "|" + native, NodeType: nt,
		Provider: "gcp", Account: realm, ARN: native,
		Attributes: map[string]any{"synthesized": true, "member": member},
	}
	synth[member] = n
	return n
}

func splitMember(m string) (kind, val string, ok bool) {
	if m == "allUsers" || m == "allAuthenticatedUsers" {
		return m, m, true
	}
	i := strings.IndexByte(m, ':')
	if i < 0 {
		return "", "", false
	}
	kind, val = m[:i], m[i+1:]
	if strings.HasPrefix(kind, "deleted") { // deleted:serviceAccount:... — skip
		return "", "", false
	}
	// principalSet://iam.googleapis.com/... — keep the whole tail as val
	return kind, val, kind != ""
}

// isGoogleManaged reports whether an IAM member is a Google-managed service agent
// (a "robot": service-<projnum>@…, @gcp-sa-*, @cloudservices). Their roles include
// broad perms (e.g. iam.serviceAccounts.getAccessToken project-wide) that Google's
// infrastructure exercises internally — an attacker can't obtain their credentials,
// so we don't model their offensive reach (mirrors the AWS service-node exclusion).
// User-workload SAs (@<project>.iam, @appspot, <num>-compute@developer) are NOT managed.
func isGoogleManaged(member string) bool {
	kind, val, ok := splitMember(member)
	if !ok || kind != "serviceAccount" {
		return false
	}
	at := strings.IndexByte(val, '@')
	if at < 0 {
		return false
	}
	local, host := val[:at], val[at+1:]
	if host == "cloudservices.gserviceaccount.com" || strings.HasPrefix(host, "gcp-sa-") {
		return true
	}
	// service-<digits>@<google-robot-domain> (dataproc-accounts, compute-system, *-robot…)
	if rest := strings.TrimPrefix(local, "service-"); rest != local && rest != "" {
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func inTargets(nt string, targets []string) bool {
	for _, t := range targets {
		if t == nt {
			return true
		}
	}
	return false
}

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func lastSeg(s string) string {
	s = strings.TrimSuffix(s, "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// nativeOf extracts the native-id segment from NodeID (provider|account|type|native).
func nativeOf(n *model.Node) string {
	parts := strings.Split(n.NodeID, "|")
	return parts[len(parts)-1]
}

func shortName(n *model.Node) string {
	s := nativeOf(n)
	if i := strings.LastIndexAny(s, "/@"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}
