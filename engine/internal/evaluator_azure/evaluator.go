// Package evaluator_azure turns Azure RBAC facts (role_assignment + role_definition +
// deny_assignment + principal + member_of) into capability EDGES. Azure's model:
// a role ASSIGNMENT binds a principal to a role DEFINITION at a SCOPE (management group
// -> subscription -> resource group -> resource), and the grant inherits DOWNWARD to
// every resource under that scope. Role definitions carry Actions/NotActions (management
// plane) and DataActions/NotDataActions (data plane), matched with `*` wildcards.
// Deny assignments win. This mirrors evaluator_gcp with Azure-specific scope + action
// semantics; the derivation layer (project/subscription takeover, impersonation) is shared.
package evaluator_azure

import (
	"strings"
	"time"

	"thunderstorm/engine/internal/model"
)

// azCapability maps a concrete Azure action to a capability edge on a node class.
type azCapability struct {
	edge       string
	action     string // concrete action; matched against the role's (data)action patterns
	dataAction bool   // match against DataActions rather than Actions
	targets    []string
	relKind    string
	weight     float64
	verb       string
}

// The high-signal Azure capability table (action -> edge -> node class). Management-plane
// unless dataAction. Broad `*` roles (Owner/Contributor) are handled by matchAction's
// wildcard support + the subscription-takeover derivation, not enumerated here.
var capabilities = []azCapability{
	// Key Vault (data plane: RBAC data actions)
	{"CanReadSecret", "Microsoft.KeyVault/vaults/secrets/getSecret/action", true, []string{"Secret"}, "CREDENTIAL", 1.0, "can read secrets from"},
	{"CanReadSecret", "Microsoft.KeyVault/vaults/secrets/readMetadata/action", true, []string{"Secret"}, "CREDENTIAL", 0.5, "can list secrets in"},
	{"CanDecrypt", "Microsoft.KeyVault/vaults/keys/decrypt/action", true, []string{"Secret"}, "CREDENTIAL", 1.0, "can decrypt with keys in"},
	{"CanSignAs", "Microsoft.KeyVault/vaults/keys/sign/action", true, []string{"Secret"}, "AUTHORIZATION", 1.0, "can sign with keys in"},
	// Key Vault management plane: control the vault (set access policy / read via listing)
	{"CanModifyPolicy", "Microsoft.KeyVault/vaults/accessPolicies/write", false, []string{"Secret"}, "CONTROL", 1.0, "can rewrite the access policy of"},
	// Storage
	{"CanReadData", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", true, []string{"ObjectStorage"}, "DATA_ACCESS", 1.0, "can read blobs in"},
	{"CanWriteData", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write", true, []string{"ObjectStorage"}, "DATA_ACCESS", 1.0, "can write blobs in"},
	{"CanReadData", "Microsoft.Storage/storageAccounts/listkeys/action", false, []string{"ObjectStorage"}, "CREDENTIAL", 1.5, "can grab account keys (full data access) for"},
	{"CanModifyPolicy", "Microsoft.Storage/storageAccounts/listkeys/action", false, []string{"ObjectStorage"}, "CONTROL", 1.5, "can mint SAS / full control of"},
	// Compute (RCE via run-command / extensions)
	{"CanExecuteCommand", "Microsoft.Compute/virtualMachines/runCommand/action", false, []string{"VirtualMachine"}, "EXECUTION", 2.0, "can run commands on"},
	{"CanExecuteCommand", "Microsoft.Compute/virtualMachines/extensions/write", false, []string{"VirtualMachine"}, "EXECUTION", 2.0, "can deploy an RCE extension to"},
	{"CanExecuteCommand", "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", false, []string{"VirtualMachine"}, "EXECUTION", 2.0, "can run commands on"},
	// Managed identity: assign an MI to compute you control -> run as it
	{"CanPassIdentity", "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action", false, []string{"ManagedIdentity"}, "AUTHORIZATION", 2.0, "can assign"},
	// App Service / Functions / Container Apps: modify code / get creds -> run as the app MI
	{"CanModifyCode", "Microsoft.Web/sites/write", false, []string{"ApplicationPlatform"}, "EXECUTION", 2.0, "can modify"},
	{"CanExecuteCommand", "Microsoft.Web/sites/publish/action", false, []string{"ApplicationPlatform"}, "EXECUTION", 2.0, "can publish code to"},
	{"CanReadData", "Microsoft.Web/sites/publishxml/action", false, []string{"ApplicationPlatform"}, "CREDENTIAL", 1.0, "can read publish creds for"},
	// Container registry: poison images (the real push permission is a repositories data action)
	{"CanModifyCode", "Microsoft.ContainerRegistry/registries/repositories/content/write", true, []string{"ContainerRegistry"}, "EXECUTION", 1.5, "can push images to"},
	// AKS: pull cluster-admin kubeconfig / run commands (cluster takeover)
	{"CanReadSecret", "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action", false, []string{"KubernetesCluster"}, "CREDENTIAL", 2.0, "can pull cluster-admin kubeconfig for"},
	{"CanExecuteCommand", "Microsoft.ContainerService/managedClusters/runcommand/action", false, []string{"KubernetesCluster"}, "EXECUTION", 2.0, "can run commands in"},
	// Automation Accounts: author + run runbooks (run as the account's identity)
	{"CanModifyCode", "Microsoft.Automation/automationAccounts/runbooks/draft/write", false, []string{"AutomationService"}, "EXECUTION", 2.0, "can author runbooks in"},
	{"CanExecuteCommand", "Microsoft.Automation/automationAccounts/jobs/write", false, []string{"AutomationService"}, "EXECUTION", 2.0, "can run runbook jobs in"},
	{"CanExecuteCommand", "Microsoft.Automation/automationAccounts/webhooks/action", false, []string{"AutomationService"}, "EXECUTION", 2.0, "can trigger runbooks in"},
	// Logic Apps: rewrite + trigger the workflow (runs as its connections/MI)
	{"CanModifyCode", "Microsoft.Logic/workflows/write", false, []string{"Workflow"}, "EXECUTION", 1.5, "can rewrite the workflow of"},
	{"CanTrigger", "Microsoft.Logic/workflows/triggers/run/action", false, []string{"Workflow"}, "EXECUTION", 1.5, "can trigger"},
	// Storage: mint SAS (full data access without the keys)
	{"CanModifyPolicy", "Microsoft.Storage/storageAccounts/listServiceSas/action", false, []string{"ObjectStorage"}, "CONTROL", 1.5, "can mint a service SAS for"},
	{"CanModifyPolicy", "Microsoft.Storage/storageAccounts/listAccountSas/action", false, []string{"ObjectStorage"}, "CONTROL", 1.5, "can mint an account SAS for"},
	// App Service / Functions: host+function keys, app-settings/connection-string secrets
	{"CanReadSecret", "Microsoft.Web/sites/host/listkeys/action", false, []string{"ApplicationPlatform"}, "CREDENTIAL", 1.5, "can read host/master keys for"},
	{"CanExecuteCommand", "Microsoft.Web/sites/functions/listkeys/action", false, []string{"ApplicationPlatform"}, "EXECUTION", 1.5, "can invoke functions on"},
	{"CanReadData", "Microsoft.Web/sites/config/list/action", false, []string{"ApplicationPlatform"}, "CREDENTIAL", 1.5, "can read app settings/connection strings for"},
	// Key Vault: reconfigure the vault (swap auth model) / export keys
	{"CanModifyPolicy", "Microsoft.KeyVault/vaults/write", false, []string{"Secret"}, "CONTROL", 1.5, "can reconfigure the auth model of"},
	{"CanExportKey", "Microsoft.KeyVault/vaults/keys/exportKey/action", true, []string{"Secret"}, "CREDENTIAL", 1.5, "can export keys from"},
	// VMSS fleet-wide extension RCE
	{"CanExecuteCommand", "Microsoft.Compute/virtualMachineScaleSets/extensions/write", false, []string{"VirtualMachine"}, "EXECUTION", 2.0, "can deploy an RCE extension across"},
	// VM reconfigure (attach an identity you can then run as — pairs with CanPassIdentity)
	{"CanModifyConfiguration", "Microsoft.Compute/virtualMachines/write", false, []string{"VirtualMachine"}, "CONTROL", 1.5, "can reconfigure (attach identity to)"},
	// Authorization: grant roles at a scope = self-grant Owner = takeover (-> subscription node)
	{"CanGrantPermission", "Microsoft.Authorization/roleAssignments/write", false, []string{"Subscription", "ResourceGroup", "ManagementGroup"}, "CONTROL", 2.0, "can assign roles at"},
	{"CanGrantPermission", "Microsoft.Authorization/elevateAccess/action", false, []string{"Subscription", "ManagementGroup"}, "CONTROL", 2.0, "can elevate access at"},
}

type assignment struct {
	principal string
	roleDef   string
	scope     string
	condition string
	factID    string // fact_id of the role_assignment fact (provenance)
}

type roleDef struct {
	actions, notActions, dataActions, notDataActions []string
}

// denyRule is a deny assignment's coverage: an action set at a scope. Deny wins.
type denyRule struct {
	scope               string
	actions, notActions []string
}

// EvaluatePermissions turns RBAC facts into capability edges, synthesizing identity
// nodes for principals and a Subscription node per account. Returns (edges, extraNodes).
func EvaluatePermissions(facts []model.Fact, nodes []model.Node, at time.Time) ([]model.Edge, []model.Node) {
	roles := map[string]roleDef{}
	var assigns []assignment
	denyActs := map[string][]denyRule{}   // principalId -> deny rules (deny-wins)
	groupMembers := map[string][]string{} // groupId -> member principalIds (transitive)
	principals := map[string]map[string]any{}
	mgChildren := map[string][]string{}  // MG name -> child names
	mgChildType := map[string]string{}   // child name -> "managementGroup" | "subscription"
	publicContainer := map[string]bool{} // storage ARN (lower) -> has a confirmed public container
	groupOwners := map[string][]string{} // groupId -> owner principalIds (owner can add self)
	for _, f := range facts {
		switch f.Kind {
		case "mg_hierarchy":
			mgChildren[f.Source] = append(mgChildren[f.Source], f.Target)
			mgChildType[f.Target] = str(f.Attributes["childType"])
		case "public_container":
			publicContainer[strings.ToLower(f.Source)] = true
		case "entra_group_owner":
			groupOwners[f.Target] = append(groupOwners[f.Target], f.Source)
		case "role_definition":
			roles[roleDefKey(f.Source)] = roleDef{
				actions:        toStrings(f.Attributes["actions"]),
				notActions:     toStrings(f.Attributes["notActions"]),
				dataActions:    toStrings(f.Attributes["dataActions"]),
				notDataActions: toStrings(f.Attributes["notDataActions"]),
			}
		case "role_assignment":
			assigns = append(assigns, assignment{
				principal: f.Source, scope: f.Target,
				roleDef:   roleDefKey(str(f.Attributes["roleDefinitionId"])),
				condition: str(f.Attributes["condition"]),
				factID:    model.FactID(f),
			})
		case "deny_assignment":
			denyActs[f.Source] = append(denyActs[f.Source], denyRule{
				scope: f.Target, actions: toStrings(f.Attributes["actions"]),
				notActions: toStrings(f.Attributes["notActions"])})
		case "principal":
			principals[f.Source] = f.Attributes
		case "member_of":
			groupMembers[f.Target] = append(groupMembers[f.Target], f.Source)
		}
	}

	// group RBAC: members of a group inherit that group's role assignments (member_of is
	// transitive from the Graph query), so expand each group assignment to its members.
	for _, a := range assigns {
		for _, m := range groupMembers[a.principal] {
			assigns = append(assigns, assignment{principal: m, roleDef: a.roleDef, scope: a.scope, condition: a.condition, factID: a.factID})
		}
	}

	// resource node index: by id and by node type; discover the accounts (subscriptions).
	// Also index nodes by their Entra principalId (managed identities + system-assigned
	// identities on VMs/apps) so a role assignment TO that identity attaches to the same
	// node it appears as in inventory — the pass-identity / run-as chain depends on it.
	byType := map[string][]*model.Node{}
	byID := map[string]*model.Node{}
	byPrincipalID := map[string]*model.Node{}
	accounts := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		byType[n.NodeType] = append(byType[n.NodeType], n)
		if n.ARN != "" {
			byID[strings.ToLower(n.ARN)] = n
		}
		if n.Account != "" {
			accounts[n.Account] = true
		}
		if pid := principalIDOf(n); pid != "" {
			byPrincipalID[pid] = n
		}
	}

	synth := map[string]*model.Node{}
	// synthesize a Subscription node per account so subscription-scope grants + takeover attach.
	subNode := map[string]*model.Node{}
	for acct := range accounts {
		id := "azure|" + acct + "|azure:resourcemanager:subscription|/subscriptions/" + acct
		n := &model.Node{NodeID: id, NodeType: "Subscription", Provider: "azure", Account: acct,
			ARN: "/subscriptions/" + acct, Attributes: map[string]any{"synthesized": true}}
		synth[id] = n
		subNode[acct] = n
		byType["Subscription"] = append(byType["Subscription"], n)
	}

	// management-group tree: MG -> its descendant subscription ids (transitive), so an
	// MG-scoped grant reaches exactly those subs — not every subscription in view.
	mgSubs := map[string]map[string]bool{}
	var descend func(mg string, seen map[string]bool) []string
	descend = func(mg string, seen map[string]bool) []string {
		if seen[mg] {
			return nil
		}
		seen[mg] = true
		var subs []string
		for _, ch := range mgChildren[mg] {
			if mgChildType[ch] == "subscription" {
				subs = append(subs, ch)
			} else {
				subs = append(subs, descend(ch, seen)...)
			}
		}
		return subs
	}
	allMGs := map[string]bool{}
	for mg := range mgChildren {
		allMGs[mg] = true
	}
	for ch, t := range mgChildType {
		if t == "managementGroup" {
			allMGs[ch] = true
		}
	}
	mgNode := map[string]*model.Node{}
	for mg := range allMGs {
		s := map[string]bool{}
		for _, sub := range descend(mg, map[string]bool{}) {
			s[sub] = true
		}
		mgSubs[mg] = s
		arn := "/providers/Microsoft.Management/managementGroups/" + mg
		id := "azure|tenant|azure:management:managementgroup|" + arn
		n := &model.Node{NodeID: id, NodeType: "ManagementGroup", Provider: "azure", Account: "tenant",
			ARN: arn, Attributes: map[string]any{"synthesized": true, "displayName": mg}}
		synth[id] = n
		mgNode[mg] = n
		byType["ManagementGroup"] = append(byType["ManagementGroup"], n)
	}

	// resource-group nodes (parsed from resource ARNs) so an RG-scoped Owner owns exactly
	// that RG — not the whole subscription.
	rgNode := map[string]*model.Node{}
	for i := range nodes {
		rg := rgScopeOf(nodes[i].ARN)
		if rg == "" {
			continue
		}
		key := strings.ToLower(rg)
		if _, ok := rgNode[key]; ok {
			continue
		}
		id := "azure|" + nodes[i].Account + "|azure:resourcemanager:resourcegroup|" + rg
		n := &model.Node{NodeID: id, NodeType: "ResourceGroup", Provider: "azure", Account: nodes[i].Account,
			ARN: rg, Attributes: map[string]any{"synthesized": true, "displayName": lastSeg(rg)}}
		synth[id] = n
		rgNode[key] = n
		byType["ResourceGroup"] = append(byType["ResourceGroup"], n)
	}

	// scopeCovers: like scopeContains, but an MG scope covers only the subscriptions actually
	// under that MG (from mgSubs); unknown MGs stay conservative (cover all).
	scopeCovers := func(scope, resourceID string) bool {
		const mgp = "/providers/Microsoft.Management/managementGroups/"
		if strings.HasPrefix(scope, mgp) {
			subs := mgSubs[scope[len(mgp):]]
			if subs == nil {
				return true
			}
			return subs[subOf(resourceID)]
		}
		return scopeContains(scope, resourceID)
	}

	var edges []model.Edge
	emitted := map[string]int{}
	emit := func(cap azCapability, src, res *model.Node, cond bool, facts []string) {
		if src == nil || res == nil || src.NodeID == res.NodeID {
			return
		}
		id := model.EdgeID(cap.edge, src.NodeID, res.NodeID, res.ARN)
		if idx, ok := emitted[id]; ok {
			if !cond && edges[idx].State == model.StateConditional {
				edges[idx].State = model.StateActive
				edges[idx].Confidence = 1.0
			}
			return
		}
		state, conf := model.StateActive, 1.0
		if cond {
			state, conf = model.StateConditional, 0.5
		}
		emitted[id] = len(edges)
		edges = append(edges, model.Edge{
			EdgeID: id, Type: cap.edge, Source: src.NodeID, Target: res.NodeID,
			RelationshipKind: cap.relKind, Nature: model.NatureExplicit, Provider: "azure",
			State: state, Confidence: conf, Weight: cap.weight, Scope: res.ARN,
			Permissions: []string{cap.action},
			Facts:       facts, // provenance: the role_assignment fact behind this grant
			Evidence:    map[string]any{"via": "role-assignment", "action": cap.action},
			Narrative:   shortName(src) + " " + cap.verb + " " + shortName(res),
			FirstSeen:   at,
		})
	}

	resolve := func(pid string) *model.Node {
		if n, ok := byPrincipalID[pid]; ok {
			return n // unify: the role holder IS the inventoried identity/resource node
		}
		return resolvePrincipal(pid, principals, byID, synth)
	}

	for _, a := range assigns {
		rd, ok := roles[a.roleDef]
		if !ok {
			continue
		}
		src := resolve(a.principal)
		if src == nil {
			continue
		}
		for _, cap := range capabilities {
			granted, denied := rd.dataActions, rd.notDataActions
			if !cap.dataAction {
				granted, denied = rd.actions, rd.notActions
			}
			if !anyMatch(granted, cap.action) || anyMatch(denied, cap.action) {
				continue
			}
			// the grant applies to every resource of cap.targets that lies under a.scope,
			// unless a deny assignment for this principal covers the action at that scope.
			for _, t := range cap.targets {
				for _, res := range byType[t] {
					if !scopeCovers(a.scope, res.ARN) {
						continue
					}
					if deniedFor(denyActs[a.principal], cap.action, res.ARN) {
						continue
					}
					emit(cap, src, res, a.condition != "", fslice(a.factID))
				}
			}
		}
	}

	// scope-aware container takeover: whoever can rewrite the IAM policy of a management
	// group or resource group owns exactly what's under it — an MG cascades to its
	// descendant subscriptions, an RG to only its own resources. (Subscription takeover is
	// handled account-wide in derive.go.) control-implies-read then yields the secrets.
	takeover := func(srcID string, tgt *model.Node) {
		id := model.EdgeID("CanControl", srcID, tgt.NodeID, tgt.ARN)
		if _, ok := emitted[id]; ok {
			return
		}
		emitted[id] = len(edges)
		edges = append(edges, model.Edge{
			EdgeID: id, Type: "CanControl", Source: srcID, Target: tgt.NodeID,
			RelationshipKind: "CONTROL", Nature: model.NatureDerived, Provider: "azure",
			State: model.StateActive, Confidence: 0.9, Weight: 2.0, Scope: tgt.ARN,
			Evidence:  map[string]any{"via": "container-takeover"},
			Narrative: "owns " + shortName(tgt) + " via container takeover", FirstSeen: at,
		})
	}
	for _, e := range append([]model.Edge{}, edges...) { // snapshot: we append inside
		if e.Type != "CanGrantPermission" {
			continue
		}
		for mg, n := range mgNode {
			if e.Target == n.NodeID {
				for sub := range mgSubs[mg] {
					if sn := subNode[sub]; sn != nil {
						takeover(e.Source, sn) // -> derive.go subscription-takeover cascades
					}
				}
			}
		}
		for key, n := range rgNode {
			if e.Target == n.NodeID {
				for i := range nodes {
					if strings.HasPrefix(strings.ToLower(nodes[i].ARN), key+"/") {
						takeover(e.Source, &nodes[i])
					}
				}
			}
		}
	}

	// Entra (directory) escalation: directory roles + Graph app-role grants + ownership,
	// with group grants inherited by members AND owners, and PIM-eligible roles conditional.
	edges = append(edges, evaluateEntra(facts, byType, resolve, synth, groupMembers, groupOwners, at)...)

	// exposure: public-network / anonymous-access resources (from ARG properties + confirmed containers).
	edges = append(edges, azureExposures(nodes, synth, publicContainer, at)...)

	extra := make([]model.Node, 0, len(synth))
	for _, n := range synth {
		extra = append(extra, *n)
	}
	return edges, extra
}

// Well-known Entra directory-role template IDs (built-in roles).
const (
	roleGlobalAdmin   = "62e90394-69f5-4237-9190-012177145e10"
	rolePrivRoleAdmin = "e8611ab8-c189-46e8-94e1-60213ab1f814"
	roleAppAdmin      = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
	roleCloudAppAdmin = "158c047a-c907-4556-b7ef-446551a6b5f7"
	rolePrivAuthAdmin = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
	roleUserAdmin     = "fe930be7-5e62-47db-91af-98c3a49a38b1"
	roleGroupsAdmin   = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
	roleAuthAdmin     = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
)

// Well-known Microsoft Graph application-permission (app-role) IDs — the tenant-takeover
// primitives when granted to a service principal as an application permission.
const (
	graphRoleMgmtRW    = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" // RoleManagement.ReadWrite.Directory
	graphAppRoleAssign = "06b708a9-e830-4db3-a914-8e69da51d44f" // AppRoleAssignment.ReadWrite.All
	graphAppRW         = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" // Application.ReadWrite.All
	graphDirRW         = "19dbc75e-c2e2-444c-a770-ec69d8559fc7" // Directory.ReadWrite.All
	graphGroupRW       = "62a82d76-70ea-41e2-9197-370581804d09" // Group.ReadWrite.All
)

// evaluateEntra turns Entra directory-role + Graph app-role facts into capability edges.
// The Entra plane is where tenant takeover usually runs: Global Admin owns the tenant;
// Privileged Role Admin / RoleManagement.ReadWrite.Directory can self-grant Global Admin;
// Application Admin / Application.ReadWrite.All can add a credential to any service
// principal and thus impersonate it. A synthesized Tenant node anchors takeover.
func evaluateEntra(facts []model.Fact, byType map[string][]*model.Node,
	resolve func(string) *model.Node, synth map[string]*model.Node,
	groupMembers, groupOwners map[string][]string, at time.Time) []model.Edge {
	tenantID := "azure|tenant|azure:entra:tenant|tenant"
	tenant, ok := synth[tenantID]
	if !ok {
		tenant = &model.Node{NodeID: tenantID, NodeType: "Tenant", Provider: "azure",
			Account: "tenant", ARN: "tenant",
			Attributes: map[string]any{"synthesized": true, "displayName": "Entra Tenant"}}
		synth[tenantID] = tenant
	}
	sps := append(append([]*model.Node{}, byType["ServiceIdentity"]...), byType["ApplicationIdentity"]...)
	var edges []model.Edge
	seen := map[string]int{} // edge id -> index (promote CONDITIONAL -> ACTIVE, never downgrade)
	var curFact string       // fact_id of the entra fact being processed (set in the fact loop)
	emit := func(src, tgt *model.Node, edge, relKind, verb string, cond bool) {
		if src == nil || tgt == nil || src.NodeID == tgt.NodeID {
			return
		}
		id := model.EdgeID(edge, src.NodeID, tgt.NodeID, tgt.ARN)
		if idx, ok := seen[id]; ok {
			if !cond && edges[idx].State == model.StateConditional {
				edges[idx].State, edges[idx].Confidence = model.StateActive, 1.0
			}
			return
		}
		state, conf := model.StateActive, 1.0
		if cond {
			state, conf = model.StateConditional, 0.5 // PIM-eligible: requires self-activation
		}
		seen[id] = len(edges)
		edges = append(edges, model.Edge{
			EdgeID: id, Type: edge, Source: src.NodeID, Target: tgt.NodeID,
			RelationshipKind: relKind, Nature: model.NatureExplicit, Provider: "azure",
			State: state, Confidence: conf, Weight: 2.0, Scope: tgt.ARN,
			Facts:     fslice(curFact), // provenance: the entra fact currently being processed
			Evidence:  map[string]any{"via": "entra"},
			Narrative: shortName(src) + " " + verb + " " + shortName(tgt), FirstSeen: at,
		})
	}
	toAllSPs := func(src *model.Node, edge, verb string, cond bool) {
		for _, sp := range sps {
			emit(src, sp, edge, "CREDENTIAL", verb, cond)
		}
	}
	// principals who effectively hold a group's grant: the group itself, its members, and
	// its owners (an owner can add themselves). For a non-group principal this is just it.
	expand := func(src string) []*model.Node {
		out := []*model.Node{resolve(src)}
		for _, m := range groupMembers[src] {
			out = append(out, resolve(m))
		}
		for _, o := range groupOwners[src] {
			out = append(out, resolve(o))
		}
		return out
	}
	// directory-role capability mapping (cond=true for PIM-eligible: one activation away).
	dirRole := func(src *model.Node, roleTemplateID string, cond bool) {
		switch roleTemplateID {
		case roleGlobalAdmin:
			emit(src, tenant, "CanControl", "CONTROL", "is Global Administrator over", cond)
		case rolePrivRoleAdmin:
			emit(src, tenant, "CanGrantPermission", "CONTROL", "can grant any directory role in", cond)
		case roleAppAdmin, roleCloudAppAdmin:
			toAllSPs(src, "CanCreateCredentialFor", "can add credentials to", cond)
		case rolePrivAuthAdmin:
			for _, u := range byType["HumanIdentity"] {
				emit(src, u, "CanResetCredential", "CREDENTIAL", "can reset credentials of", cond)
			}
		case roleUserAdmin, roleAuthAdmin:
			for _, u := range byType["HumanIdentity"] {
				emit(src, u, "CanResetCredential", "CREDENTIAL", "can reset the password of", cond)
			}
		case roleGroupsAdmin:
			for _, g := range byType["Group"] {
				emit(src, g, "CanAddMember", "CONTROL", "can add members to", cond)
			}
		}
	}
	appRole := func(src *model.Node, appRoleID string, cond bool) {
		switch appRoleID {
		case graphRoleMgmtRW, graphAppRoleAssign:
			emit(src, tenant, "CanGrantPermission", "CONTROL", "can self-grant directory roles in", cond)
		case graphDirRW:
			emit(src, tenant, "CanControl", "CONTROL", "can write any object in", cond)
		case graphAppRW:
			toAllSPs(src, "CanCreateCredentialFor", "can add credentials to", cond)
		case graphGroupRW:
			for _, g := range byType["Group"] {
				emit(src, g, "CanAddMember", "CONTROL", "can add itself to", cond)
			}
		}
	}
	for _, f := range facts {
		curFact = model.FactID(f) // stamped onto every edge emitted while processing this fact
		switch f.Kind {
		case "entra_role_assignment":
			for _, s := range expand(f.Source) {
				dirRole(s, str(f.Attributes["roleTemplateId"]), false)
			}
		case "entra_role_eligible": // PIM: eligible = one self-activation away -> CONDITIONAL
			for _, s := range expand(f.Source) {
				dirRole(s, str(f.Attributes["roleTemplateId"]), true)
			}
		case "entra_app_role":
			for _, s := range expand(f.Source) {
				appRole(s, str(f.Attributes["appRoleId"]), false)
			}
		case "entra_owner":
			// owner of a service principal can add a credential to it and impersonate it.
			emit(resolve(f.Source), resolve(f.Target), "CanCreateCredentialFor", "CREDENTIAL",
				"owns (can add credentials to)", false)
		case "entra_group_owner":
			// owner of a group can add itself to the group (and inherit its grants via expand).
			emit(resolve(f.Source), resolve(f.Target), "CanAddMember", "CONTROL",
				"owns (can add itself to)", false)
		}
	}
	return edges
}

// azureExposures derives ExposedToInternet edges from the ARG `properties` already on
// each node: anonymous blob access, and public network access with no restricting ACL.
// The viz surfaces these in the Exposures tab and on the graph (-> AnonymousIdentity).
func azureExposures(nodes []model.Node, synth map[string]*model.Node, publicContainer map[string]bool, at time.Time) []model.Edge {
	anonID := "azure|internet|azure:internet:anonymous|Anonymous"
	anon := func() *model.Node {
		if n, ok := synth[anonID]; ok {
			return n
		}
		n := &model.Node{NodeID: anonID, NodeType: "AnonymousIdentity", Provider: "azure",
			Account: "internet", ARN: "Anonymous",
			Attributes: map[string]any{"synthesized": true, "displayName": "Anonymous / Internet"}}
		synth[anonID] = n
		return n
	}
	var edges []model.Edge
	emit := func(res *model.Node, detail, severity string) {
		a := anon()
		id := model.EdgeID("ExposedToInternet", res.NodeID, a.NodeID, res.ARN)
		edges = append(edges, model.Edge{
			EdgeID: id, Type: "ExposedToInternet", Source: res.NodeID, Target: a.NodeID,
			RelationshipKind: "NETWORK", Nature: model.NatureExplicit, Provider: "azure",
			State: model.StateActive, Confidence: 1.0, Weight: 1.0, Scope: res.ARN,
			Evidence:  map[string]any{"exposure": detail, "severity": severity},
			Narrative: shortName(res) + " " + detail, FirstSeen: at,
		})
	}
	for i := range nodes {
		n := &nodes[i]
		p, _ := n.Attributes["properties"].(map[string]any)
		if p == nil {
			continue
		}
		netOpen := networkDefaultAllow(p)
		// allowBlobPublicAccess is the account-level toggle that PERMITS anonymous blob
		// access — actual public data still requires a container with publicAccess !=
		// None (a data-plane sub-resource we don't enumerate), so this is a "permits"
		// finding, not confirmed public. (Confirming needs container enumeration — TODO.)
		if b, ok := p["allowBlobPublicAccess"].(bool); ok && b {
			if publicContainer[strings.ToLower(n.ARN)] {
				// CONFIRMED: a container with public access exists -> anonymously readable now.
				emit(n, "has a CONFIRMED public blob container (anonymously readable over the internet)", "critical")
				continue
			}
			sev := "medium"
			if netOpen {
				sev = "high"
			}
			emit(n, "permits anonymous public blob access (account setting; a public container would be internet-readable)", sev)
			continue
		}
		if pna, ok := p["publicNetworkAccess"].(string); ok && strings.EqualFold(pna, "Enabled") {
			emit(n, "is reachable over the public internet (public network access enabled)", "high")
		}
	}
	return edges
}

// resolvePrincipal maps a principal GUID to a graph node: an existing MI/resource node,
// or a synthesized identity node labeled from the `principal` fact.
func resolvePrincipal(pid string, principals map[string]map[string]any, byID map[string]*model.Node, synth map[string]*model.Node) *model.Node {
	if n, ok := synth["p:"+pid]; ok {
		return n
	}
	attrs := principals[pid]
	name := pid
	ptype := "ServicePrincipal"
	if attrs != nil {
		if dn := str(attrs["displayName"]); dn != "" {
			name = dn
		}
		if t := str(attrs["type"]); t != "" {
			ptype = t
		}
	}
	nodeType := map[string]string{
		"User": "HumanIdentity", "Group": "Group", "ServicePrincipal": "ServiceIdentity",
		"Application": "ApplicationIdentity", "ManagedIdentity": "ManagedIdentity",
	}[ptype]
	if nodeType == "" {
		nodeType = "ServiceIdentity"
	}
	n := &model.Node{
		NodeID: "azure|entra|azure:entra:" + strings.ToLower(ptype) + "|" + pid, NodeType: nodeType,
		Provider: "azure", Account: "entra", ARN: pid,
		Attributes: map[string]any{"synthesized": true, "displayName": name, "principalId": pid},
	}
	synth["p:"+pid] = n
	return n
}

// deniedFor reports whether a deny assignment covers the action at the resource scope
// (deny-wins). A deny matches when its scope contains the resource, its actions match
// the action, and its notActions do not exclude it.
func deniedFor(rules []denyRule, action, resourceID string) bool {
	for _, d := range rules {
		if !scopeContains(d.scope, resourceID) {
			continue
		}
		if anyMatch(d.actions, action) && !anyMatch(d.notActions, action) {
			return true
		}
	}
	return false
}

// scopeContains reports whether an assignment scope covers a resource id. Root ("/")
// and management-group scopes cover everything in view; subscription/RG/resource scopes
// are prefix matches on the ARM id.
func scopeContains(scope, resourceID string) bool {
	if scope == "" || resourceID == "" {
		return false
	}
	if scope == "/" {
		return true
	}
	if strings.HasPrefix(scope, "/providers/Microsoft.Management/managementGroups/") {
		return true // MG hierarchy not yet expanded; MG scope covers all in-view subs
	}
	s, r := strings.ToLower(strings.TrimRight(scope, "/")), strings.ToLower(resourceID)
	return r == s || strings.HasPrefix(r, s+"/")
}

// fslice returns a single-element fact slice (or nil) for stamping edge provenance.
func fslice(id string) []string {
	if id == "" {
		return nil
	}
	return []string{id}
}
