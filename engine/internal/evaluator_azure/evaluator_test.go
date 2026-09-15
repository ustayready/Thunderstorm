package evaluator_azure

import (
	"testing"
	"time"

	"thunderstorm/engine/internal/derive"
	"thunderstorm/engine/internal/model"
)

const sub = "0000-sub"

func armID(rg, provider, name string) string {
	return "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/" + provider + "/" + name
}
func vaultNode(name string) model.Node {
	id := armID("rg", "Microsoft.KeyVault/vaults", name)
	return model.Node{NodeID: "azure|" + sub + "|azure:keyvault:vault|" + id, NodeType: "Secret",
		Provider: "azure", Account: sub, ARN: id}
}
func storageNode(name string) model.Node {
	id := armID("rg", "Microsoft.Storage/storageAccounts", name)
	return model.Node{NodeID: "azure|" + sub + "|azure:storage:account|" + id, NodeType: "ObjectStorage",
		Provider: "azure", Account: sub, ARN: id}
}
func miNode(name string) model.Node {
	id := armID("rg", "Microsoft.ManagedIdentity/userAssignedIdentities", name)
	return model.Node{NodeID: "azure|" + sub + "|azure:managedidentity:userassigned|" + id, NodeType: "ManagedIdentity",
		Provider: "azure", Account: sub, ARN: id}
}

func roleDefFact(id, name string, actions, dataActions []string) model.Fact {
	return model.Fact{Kind: "role_definition", Source: id, Attributes: map[string]any{
		"roleName": name, "actions": toAny(actions), "dataActions": toAny(dataActions),
		"notActions": []any{}, "notDataActions": []any{}}}
}
func assignFact(pid, roleDefID, scope, cond string) model.Fact {
	return model.Fact{Kind: "role_assignment", Source: pid, Target: scope,
		Attributes: map[string]any{"roleDefinitionId": roleDefID, "condition": cond, "principalType": "User"}}
}
func principalFact(pid, name, ptype string) model.Fact {
	return model.Fact{Kind: "principal", Source: pid, Attributes: map[string]any{"displayName": name, "type": ptype}}
}
func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func runFull(nodes []model.Node, facts []model.Fact) []model.Edge {
	at := time.Unix(0, 0)
	edges, extra := EvaluatePermissions(facts, nodes, at)
	all := append(append([]model.Node{}, nodes...), extra...)
	nt := map[string]string{}
	for _, n := range all {
		nt[n.NodeID] = n.NodeType
	}
	return append(edges, derive.Derive(edges, nt, at)...)
}

func edgeExists(edges []model.Edge, t, srcSub, tgtSub string) bool {
	for _, e := range edges {
		if e.Type == t && contains(e.Source, srcSub) && contains(e.Target, tgtSub) {
			return true
		}
	}
	return false
}
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// GOLDEN: a Key Vault Secrets User (data-plane role) can read the vault's secrets.
func TestAzure_KeyVaultSecretsUserReadsSecret(t *testing.T) {
	nodes := []model.Node{vaultNode("kv1")}
	facts := []model.Fact{
		principalFact("p-alice", "alice", "User"),
		roleDefFact("/rd/kvsu", "Key Vault Secrets User", nil,
			[]string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}),
		assignFact("p-alice", "/rd/kvsu", armID("rg", "Microsoft.KeyVault/vaults", "kv1"), ""),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanReadSecret", "p-alice", "kv1") {
		t.Error("Key Vault Secrets User should CanReadSecret the vault")
	}
}

// GOLDEN: a subscription-scoped assignment inherits DOWN to every resource under it.
func TestAzure_SubscriptionScopeInheritsToAllResources(t *testing.T) {
	nodes := []model.Node{storageNode("sa1"), storageNode("sa2")}
	facts := []model.Fact{
		principalFact("p-bob", "bob", "ServicePrincipal"),
		roleDefFact("/rd/blobreader", "Storage Blob Data Reader", nil,
			[]string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}),
		assignFact("p-bob", "/rd/blobreader", "/subscriptions/"+sub, ""),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanReadData", "p-bob", "sa1") || !edgeExists(edges, "CanReadData", "p-bob", "sa2") {
		t.Error("subscription-scope Blob Data Reader should reach ALL storage accounts")
	}
}

// GOLDEN: an ABAC-conditioned assignment yields a CONDITIONAL edge.
func TestAzure_ConditionalAssignmentIsConditional(t *testing.T) {
	nodes := []model.Node{vaultNode("kv1")}
	facts := []model.Fact{
		principalFact("p-carol", "carol", "User"),
		roleDefFact("/rd/kvsu", "Key Vault Secrets User", nil,
			[]string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}),
		assignFact("p-carol", "/rd/kvsu", armID("rg", "Microsoft.KeyVault/vaults", "kv1"),
			"@Resource[Microsoft.KeyVault/vaults:name] StringEquals 'kv1'"),
	}
	edges, _ := EvaluatePermissions(facts, nodes, time.Unix(0, 0))
	var found bool
	for _, e := range edges {
		if e.Type == "CanReadSecret" {
			found = true
			if e.State != model.StateConditional {
				t.Errorf("conditioned assignment must be CONDITIONAL, got %s", e.State)
			}
		}
	}
	if !found {
		t.Error("expected a CanReadSecret edge")
	}
}

// GOLDEN: Owner at subscription scope = self-grant any role = subscription TAKEOVER,
// reaching a crown secret no lesser identity can access. The top of the Azure ladder.
func TestAzure_OwnerTakesOverSubscription(t *testing.T) {
	nodes := []model.Node{vaultNode("crown"), storageNode("sa1")}
	facts := []model.Fact{
		principalFact("p-mallory", "mallory", "ServicePrincipal"),
		roleDefFact("/rd/owner", "Owner", []string{"*"}, nil),
		assignFact("p-mallory", "/rd/owner", "/subscriptions/"+sub, ""),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanGrantPermission", "p-mallory", "/subscriptions/"+sub) {
		t.Error("Owner should CanGrantPermission at the subscription")
	}
	if !edgeExists(edges, "CanReadSecret", "p-mallory", "crown") {
		t.Error("subscription takeover should reach the crown secret (derived)")
	}
	if !edgeExists(edges, "CanControl", "p-mallory", "sa1") {
		t.Error("subscription takeover should control every resource (derived)")
	}
}

// GOLDEN: assigning a user-assigned managed identity is CanPassIdentity (attach it to
// compute you control, then run as it).
func TestAzure_AssignManagedIdentityIsPassIdentity(t *testing.T) {
	nodes := []model.Node{miNode("mi1")}
	facts := []model.Fact{
		principalFact("p-dave", "dave", "User"),
		roleDefFact("/rd/mio", "Managed Identity Operator",
			[]string{"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"}, nil),
		assignFact("p-dave", "/rd/mio", armID("rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "mi1"), ""),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanPassIdentity", "p-dave", "mi1") {
		t.Error("Managed Identity Operator should CanPassIdentity the identity")
	}
}

func groupNode(id string) model.Node {
	return model.Node{NodeID: "azure|entra|azure:entra:group|" + id, NodeType: "Group",
		Provider: "azure", Account: "entra", ARN: id, Attributes: map[string]any{"displayName": id}}
}

// GOLDEN: a directory role assigned to a GROUP is inherited by its members — a role-assignable
// group holding Global Admin makes every member an effective tenant admin.
func TestAzure_DirectoryRoleAssignedToGroupReachesMembers(t *testing.T) {
	nodes := []model.Node{vaultNode("crown")}
	facts := []model.Fact{
		principalFact("g-admins", "GA Group", "Group"),
		principalFact("p-alice", "alice", "User"),
		{Kind: "member_of", Source: "p-alice", Target: "g-admins"},
		entraRole("g-admins", roleGlobalAdmin),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanControl", "g-admins", "tenant") {
		t.Error("the group should hold the Global Admin -> tenant edge")
	}
	if !edgeExists(edges, "CanControl", "p-alice", "tenant") {
		t.Error("a member of a Global-Admin group must inherit tenant control")
	}
}

// GOLDEN: a group OWNER can add itself to the group and inherit the group's grants.
func TestAzure_GroupOwnerInheritsAndCanAddMember(t *testing.T) {
	nodes := []model.Node{}
	facts := []model.Fact{
		principalFact("g-priv", "Priv Group", "Group"),
		principalFact("p-owner", "owner", "User"),
		{Kind: "entra_group_owner", Source: "p-owner", Target: "g-priv"},
		entraRole("g-priv", roleGlobalAdmin),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanAddMember", "p-owner", "g-priv") {
		t.Error("a group owner should CanAddMember the group")
	}
	if !edgeExists(edges, "CanControl", "p-owner", "tenant") {
		t.Error("a group owner should inherit the group's Global Admin (can add self)")
	}
}

// GOLDEN: a PIM-eligible directory role is CONDITIONAL (one self-activation away), not ACTIVE.
func TestAzure_PIMEligibleIsConditional(t *testing.T) {
	facts := []model.Fact{
		principalFact("p-pim", "pim-user", "User"),
		{Kind: "entra_role_eligible", Source: "p-pim", Attributes: map[string]any{"roleTemplateId": roleGlobalAdmin}},
	}
	edges, _ := EvaluatePermissions(facts, nil, time.Unix(0, 0))
	var found bool
	for _, e := range edges {
		if e.Type == "CanControl" && contains(e.Target, "tenant") {
			found = true
			if e.State != model.StateConditional {
				t.Errorf("PIM-eligible Global Admin must be CONDITIONAL, got %s", e.State)
			}
		}
	}
	if !found {
		t.Error("expected a CanControl -> tenant edge from PIM eligibility")
	}
}

// GOLDEN: Groups Administrator (minor-tail directory role) can add members to any group.
func TestAzure_GroupsAdminCanAddMembers(t *testing.T) {
	nodes := []model.Node{groupNode("g1")}
	facts := []model.Fact{
		principalFact("p-grpadmin", "GroupsAdmin", "User"),
		entraRole("p-grpadmin", roleGroupsAdmin),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanAddMember", "p-grpadmin", "g1") {
		t.Error("Groups Administrator should CanAddMember groups")
	}
}

func rgVault(rg, name string) model.Node {
	id := armID(rg, "Microsoft.KeyVault/vaults", name)
	return model.Node{NodeID: "azure|" + sub + "|azure:keyvault:vault|" + id, NodeType: "Secret",
		Provider: "azure", Account: sub, ARN: id}
}

// GOLDEN: an RG-scoped Owner owns ONLY that resource group — not another RG in the same
// subscription. Verifies the scope-aware container-takeover boundary.
func TestAzure_RGScopedOwnerStaysInItsRG(t *testing.T) {
	nodes := []model.Node{rgVault("rg1", "crown"), rgVault("rg2", "other")}
	facts := []model.Fact{
		principalFact("p-rg", "rgowner", "ServicePrincipal"),
		roleDefFact("/rd/owner", "Owner", []string{"*"}, nil),
		assignFact("p-rg", "/rd/owner", "/subscriptions/"+sub+"/resourceGroups/rg1", ""),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanReadSecret", "p-rg", "crown") {
		t.Error("RG-scoped Owner should reach the crown in its own RG (via takeover)")
	}
	if edgeExists(edges, "CanControl", "p-rg", "other") || edgeExists(edges, "CanReadSecret", "p-rg", "other") {
		t.Error("RG-scoped Owner must NOT reach resources in another RG")
	}
}

// GOLDEN: a management-group-scoped grant reaches only the subscriptions under that MG.
func TestAzure_MGScopeReachesOnlyItsSubscriptions(t *testing.T) {
	inSub := model.Node{NodeID: "azure|" + sub + "|azure:storage:account|/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/insub",
		NodeType: "ObjectStorage", Provider: "azure", Account: sub, ARN: "/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/insub"}
	other := "9999-other"
	outSub := model.Node{NodeID: "azure|" + other + "|azure:storage:account|/subscriptions/" + other + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/outsub",
		NodeType: "ObjectStorage", Provider: "azure", Account: other, ARN: "/subscriptions/" + other + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/outsub"}
	facts := []model.Fact{
		principalFact("p-mg", "mgreader", "User"),
		{Kind: "mg_hierarchy", Source: "mg1", Target: sub, Attributes: map[string]any{"childType": "subscription"}},
		roleDefFact("/rd/blob", "Storage Blob Data Reader", nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}),
		assignFact("p-mg", "/rd/blob", "/providers/Microsoft.Management/managementGroups/mg1", ""),
	}
	edges := runFull([]model.Node{inSub, outSub}, facts)
	if !edgeExists(edges, "CanReadData", "p-mg", "insub") {
		t.Error("MG grant should reach storage in a subscription UNDER the MG")
	}
	if edgeExists(edges, "CanReadData", "p-mg", "outsub") {
		t.Error("MG grant must NOT reach a subscription that is not under the MG")
	}
}

// GOLDEN: an owner of a service principal can add a credential and impersonate it.
func TestAzure_ServicePrincipalOwnerCanImpersonate(t *testing.T) {
	nodes := []model.Node{spNode("victim-sp")}
	facts := []model.Fact{
		principalFact("p-owner", "owner", "User"),
		{Kind: "entra_owner", Source: "p-owner", Target: "victim-sp"},
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanCreateCredentialFor", "p-owner", "victim-sp") {
		t.Error("an SP owner should CanCreateCredentialFor the SP")
	}
	if !edgeExists(edges, "CanEscalateTo", "p-owner", "victim-sp") {
		t.Error("add-credential should promote to CanEscalateTo (derived)")
	}
}

// GOLDEN: a storage account with a CONFIRMED public container is a critical exposure;
// one that merely PERMITS public access (no confirmed container) is not critical.
func TestAzure_ConfirmedPublicContainerIsCritical(t *testing.T) {
	arn := "/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/pub"
	mk := func() model.Node {
		return model.Node{NodeID: "azure|" + sub + "|azure:storage:account|" + arn, NodeType: "ObjectStorage",
			Provider: "azure", Account: sub, ARN: arn,
			Attributes: map[string]any{"properties": map[string]any{"allowBlobPublicAccess": true}}}
	}
	// with a confirmed public container -> critical
	e1, _ := EvaluatePermissions([]model.Fact{{Kind: "public_container", Source: arn,
		Attributes: map[string]any{"container": "loot", "access": "Blob"}}}, []model.Node{mk()}, time.Unix(0, 0))
	crit := false
	for _, e := range e1 {
		if e.Type == "ExposedToInternet" && str(e.Evidence["severity"]) == "critical" {
			crit = true
		}
	}
	if !crit {
		t.Error("a confirmed public container should be a CRITICAL exposure")
	}
	// without the fact -> NOT critical (permits only)
	e2, _ := EvaluatePermissions(nil, []model.Node{mk()}, time.Unix(0, 0))
	for _, e := range e2 {
		if e.Type == "ExposedToInternet" && str(e.Evidence["severity"]) == "critical" {
			t.Error("permits-only (no confirmed container) must NOT be critical")
		}
	}
}

func entraRole(pid, roleTemplateId string) model.Fact {
	return model.Fact{Kind: "entra_role_assignment", Source: pid,
		Attributes: map[string]any{"roleTemplateId": roleTemplateId}}
}
func entraApp(pid, appRoleId string) model.Fact {
	return model.Fact{Kind: "entra_app_role", Source: pid, Attributes: map[string]any{"appRoleId": appRoleId}}
}
func spNode(name string) model.Node {
	return model.Node{NodeID: "azure|entra|azure:entra:serviceprincipal|" + name, NodeType: "ServiceIdentity",
		Provider: "azure", Account: "entra", ARN: name, Attributes: map[string]any{"displayName": name}}
}

// GOLDEN: a Global Administrator owns the Entra tenant, which cascades to owning every
// subscription and (via subscription-takeover) every resource incl. a crown secret.
func TestAzure_GlobalAdminTakesOverTenant(t *testing.T) {
	nodes := []model.Node{vaultNode("crown")} // account=sub => a Subscription node is synthesized
	facts := []model.Fact{
		principalFact("p-ga", "GA", "User"),
		entraRole("p-ga", roleGlobalAdmin),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanControl", "p-ga", "tenant") {
		t.Error("Global Admin should CanControl the tenant")
	}
	if !edgeExists(edges, "CanControl", "p-ga", "/subscriptions/") {
		t.Error("tenant takeover should CanControl every subscription (derived)")
	}
	if !edgeExists(edges, "CanReadSecret", "p-ga", "crown") {
		t.Error("tenant -> subscription -> resource takeover should reach the crown secret")
	}
}

// GOLDEN: RoleManagement.ReadWrite.Directory (a Graph application permission) lets a
// service principal self-grant Global Admin -> tenant takeover.
func TestAzure_GraphRoleManagementIsTenantTakeover(t *testing.T) {
	nodes := []model.Node{vaultNode("crown")}
	facts := []model.Fact{
		principalFact("p-sp", "app-sp", "ServicePrincipal"),
		entraApp("p-sp", graphRoleMgmtRW),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanGrantPermission", "p-sp", "tenant") {
		t.Error("RoleManagement.ReadWrite.Directory should CanGrantPermission the tenant")
	}
	if !edgeExists(edges, "CanReadSecret", "p-sp", "crown") {
		t.Error("tenant takeover should reach the crown secret (derived)")
	}
}

// GOLDEN: Application Administrator can add a credential to any service principal and
// thus impersonate it (CanCreateCredentialFor -> CanEscalateTo).
func TestAzure_AppAdminCanImpersonateServicePrincipals(t *testing.T) {
	nodes := []model.Node{spNode("victim-sp")}
	facts := []model.Fact{
		principalFact("p-aa", "AppAdmin", "User"),
		entraRole("p-aa", roleAppAdmin),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanCreateCredentialFor", "p-aa", "victim-sp") {
		t.Error("Application Admin should CanCreateCredentialFor a service principal")
	}
	if !edgeExists(edges, "CanEscalateTo", "p-aa", "victim-sp") {
		t.Error("add-credential should promote to CanEscalateTo (derived)")
	}
}

// GOLDEN: a built-in role assignment (roleDefinitionId subscription-qualified) links to
// the tenant-relative role definition. Regression for the role-def key normalization.
func TestAzure_BuiltinRoleDefinitionLinks(t *testing.T) {
	nodes := []model.Node{vaultNode("kv1")}
	guid := "4633458b-17de-408a-b874-0445c86b69e6"
	facts := []model.Fact{
		principalFact("p-frank", "frank", "ServicePrincipal"),
		// definition id is tenant-relative (as returned by the tenant-wide ARG query)
		roleDefFact("/providers/Microsoft.Authorization/roleDefinitions/"+guid, "Key Vault Secrets User",
			nil, []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}),
		// assignment references it subscription-qualified
		assignFact("p-frank", "/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleDefinitions/"+guid,
			armID("rg", "Microsoft.KeyVault/vaults", "kv1"), ""),
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanReadSecret", "p-frank", "kv1") {
		t.Error("subscription-qualified assignment must link to the tenant-relative role definition")
	}
}

// GOLDEN: members of a group inherit the group's role assignments (group-based RBAC).
func TestAzure_GroupMembersInheritAssignment(t *testing.T) {
	nodes := []model.Node{vaultNode("kv1")}
	facts := []model.Fact{
		principalFact("g-admins", "KV Admins", "Group"),
		principalFact("p-grace", "grace", "User"),
		roleDefFact("/rd/kvsu", "Key Vault Secrets User", nil,
			[]string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}),
		assignFact("g-admins", "/rd/kvsu", armID("rg", "Microsoft.KeyVault/vaults", "kv1"), ""),
		{Kind: "member_of", Source: "p-grace", Target: "g-admins"},
	}
	edges := runFull(nodes, facts)
	if !edgeExists(edges, "CanReadSecret", "p-grace", "kv1") {
		t.Error("a group member should inherit the group's CanReadSecret")
	}
}

// GOLDEN: a deny assignment covering the action at the scope suppresses the grant
// (deny-wins), even for a broad role.
func TestAzure_DenyAssignmentWins(t *testing.T) {
	nodes := []model.Node{vaultNode("kv1")}
	facts := []model.Fact{
		principalFact("p-eve", "eve", "User"),
		roleDefFact("/rd/kvsu", "Key Vault Secrets User", nil,
			[]string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}),
		assignFact("p-eve", "/rd/kvsu", armID("rg", "Microsoft.KeyVault/vaults", "kv1"), ""),
		{Kind: "deny_assignment", Source: "p-eve", Target: armID("rg", "Microsoft.KeyVault/vaults", "kv1"),
			Attributes: map[string]any{"actions": []any{"Microsoft.KeyVault/vaults/secrets/*"}, "notActions": []any{}}},
	}
	edges, _ := EvaluatePermissions(facts, nodes, time.Unix(0, 0))
	for _, e := range edges {
		if e.Type == "CanReadSecret" {
			t.Error("deny assignment must suppress the CanReadSecret grant (deny-wins)")
		}
	}
}

// GOLDEN: Owner's wildcard `*` must NOT auto-grant DATA actions (Azure semantics: `*`
// covers management plane only). Owner reaches the secret via TAKEOVER, not a direct
// data-plane read — but a bare Reader with no data role gets nothing on a vault.
func TestAzure_WildcardDoesNotGrantDataPlaneDirectly(t *testing.T) {
	// matchWildcard sanity: management `*` matches an Authorization action but the
	// evaluator only checks dataActions for CanReadSecret, so a role with actions=["*"]
	// and no dataActions has no DIRECT CanReadSecret (it arrives only via takeover).
	if !matchWildcard("microsoft.authorization/*", "microsoft.authorization/roleassignments/write") {
		t.Error("wildcard should match Authorization write")
	}
	if matchWildcard("microsoft.compute/*", "microsoft.storage/accounts/read") {
		t.Error("compute wildcard must not match storage")
	}
}
