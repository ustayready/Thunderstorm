package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
)

// The Azure FACTS tier collects RBAC — role ASSIGNMENTS (principal × role × scope) and
// role DEFINITIONS (the Actions/DataActions each role grants) via Azure Resource Graph's
// AuthorizationResources, plus deny assignments, and resolves principal GUIDs to
// names/types via Microsoft Graph. The engine (evaluator_azure) turns these into
// capability EDGES over the scope hierarchy (MG -> sub -> RG -> resource).
//
// Fact kinds (consumed by the evaluator, not direct edges):
//   role_assignment  Source=principalId  Target=scope  attrs={roleDefinitionId,principalType,condition}
//   role_definition  Source=roleDefinitionId           attrs={roleName,actions,notActions,dataActions,notDataActions}
//   deny_assignment  Source=principalId  Target=scope  attrs={actions,notActions,denyAssignmentName}
//   principal        Source=principalId                attrs={displayName,type,appId}  (Entra identity label)
//   member_of        Source=memberId     Target=groupId

type factSink struct {
	b       *output.Bundle
	account string
	mu      sync.Mutex
	n       int
}

func (s *factSink) emit(f model.Fact) {
	f.CapturedAt = time.Now().UTC()
	if f.Provider == "" {
		f.Provider = "azure"
	}
	if f.Scope.Provider == "" {
		f.Scope = model.Scope{Provider: "azure", Account: s.account, Global: true}
	}
	_ = s.b.AppendJSON("facts/"+f.Kind+".ndjson", f)
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}

// CollectFacts collects Azure RBAC facts. Bulkheaded: a failure on one query is a
// ledger row, never fatal. Returns the total fact count.
func (c *Client) CollectFacts(ctx context.Context, account string, led *ledger.Ledger, b *output.Bundle, concurrency int) int {
	s := &factSink{b: b, account: account}
	principals := map[string]bool{} // principalIds seen in assignments (to resolve + expand groups)

	// 1. ROLE ASSIGNMENTS — principal × roleDefinition × scope (across all subscriptions).
	runAzFact(led, account, "azure:authorization:role-assignments", func() (int, error) {
		rows, err := c.Invoke(ctx, "arg-auth:roleassignments", "", nil)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, r := range rows {
			p := propMap(r)
			pid := str(p["principalId"])
			if pid == "" {
				continue
			}
			principals[pid] = true
			s.emit(model.Fact{Kind: "role_assignment", EdgeHint: "RoleGrants",
				Source: pid, Target: str(p["scope"]),
				Attributes: map[string]any{
					"roleDefinitionId": str(p["roleDefinitionId"]),
					"principalType":    str(p["principalType"]),
					"condition":        str(p["condition"]),
				}})
			n++
		}
		return n, nil
	})

	// 2. ROLE DEFINITIONS — the Actions/DataActions each assigned role grants.
	runAzFact(led, account, "azure:authorization:role-definitions", func() (int, error) {
		rows, err := c.Invoke(ctx, "arg-auth:roledefinitions", "", nil)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, r := range rows {
			p := propMap(r)
			id := str(r["id"])
			if id == "" {
				continue
			}
			var actions, notActions, dataActions, notDataActions []string
			for _, perm := range asSlice(p["permissions"]) {
				pm, _ := perm.(map[string]any)
				actions = append(actions, strSlice(pm["actions"])...)
				notActions = append(notActions, strSlice(pm["notActions"])...)
				dataActions = append(dataActions, strSlice(pm["dataActions"])...)
				notDataActions = append(notDataActions, strSlice(pm["notDataActions"])...)
			}
			s.emit(model.Fact{Kind: "role_definition", EdgeHint: "RoleGrants", Source: id,
				Attributes: map[string]any{
					"roleName":       str(p["roleName"]),
					"roleType":       str(p["type"]),
					"actions":        actions,
					"notActions":     notActions,
					"dataActions":    dataActions,
					"notDataActions": notDataActions,
				}})
			n++
		}
		return n, nil
	})

	// 3. DENY ASSIGNMENTS — deny-wins in the Azure model.
	runAzFact(led, account, "azure:authorization:deny-assignments", func() (int, error) {
		rows, err := c.Invoke(ctx, "arg-auth:denyassignments", "", nil)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, r := range rows {
			p := propMap(r)
			var actions, notActions []string
			for _, perm := range asSlice(p["permissions"]) {
				pm, _ := perm.(map[string]any)
				actions = append(actions, strSlice(pm["actions"])...)
				notActions = append(notActions, strSlice(pm["notActions"])...)
			}
			for _, pr := range asSlice(p["principals"]) {
				pm, _ := pr.(map[string]any)
				pid := str(pm["id"])
				if pid == "" {
					continue
				}
				s.emit(model.Fact{Kind: "deny_assignment", Source: pid, Target: str(p["scope"]),
					Attributes: map[string]any{"actions": actions, "notActions": notActions,
						"denyAssignmentName": str(p["denyAssignmentName"])}})
				n++
			}
		}
		return n, nil
	})

	// 4. ENTRA (directory) escalation — directory role assignments + Microsoft Graph
	// application-permission (app-role) grants + app/SP ownership. The Entra plane is
	// where most tenant-takeover paths run (Global Admin, RoleManagement.ReadWrite.Directory,
	// add-credential-to-any-SP), distinct from the ARM RBAC plane above.
	runAzFact(led, account, "azure:entra:directory-roles", func() (int, error) {
		return c.collectEntra(ctx, s, principals)
	})

	// 5. MANAGEMENT-GROUP hierarchy — so MG-scoped grants reach exactly the subs under them.
	runAzFact(led, account, "azure:management:hierarchy", func() (int, error) {
		return c.collectManagementGroups(ctx, s)
	})

	// 6. CONFIRMED public blob containers — upgrade "permits public access" to confirmed.
	runAzFact(led, account, "azure:storage:public-containers", func() (int, error) {
		return c.collectPublicContainers(ctx, s)
	})

	// 7. PRINCIPAL RESOLUTION — map assigned principal GUIDs to names/types via Graph.
	runAzFact(led, account, "azure:graph:principals", func() (int, error) {
		return c.resolvePrincipals(ctx, s, principals), nil
	})

	return s.n
}

// collectEntra gathers directory-role assignments, Graph app-role (application permission)
// grants, and app/SP ownership — the Entra-plane escalation inputs.
func (c *Client) collectEntra(ctx context.Context, s *factSink, principals map[string]bool) (int, error) {
	n := 0
	// directory role assignments: principal -> directory roleDefinitionId (== role template id)
	var ra struct {
		Value []struct {
			PrincipalID      string `json:"principalId"`
			RoleDefinitionID string `json:"roleDefinitionId"`
		} `json:"value"`
	}
	if err := c.graphGetJSON(ctx, "/roleManagement/directory/roleAssignments", &ra); err != nil {
		return n, err
	}
	for _, r := range ra.Value {
		if r.PrincipalID == "" {
			continue
		}
		principals[r.PrincipalID] = true
		s.emit(model.Fact{Kind: "entra_role_assignment", Source: r.PrincipalID,
			Attributes: map[string]any{"roleTemplateId": strings.ToLower(r.RoleDefinitionID)}})
		n++
	}
	// Microsoft Graph application permissions: who holds which app role on the Graph SP.
	var gsp struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := c.graphGetJSON(ctx, "/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id", &gsp); err == nil && len(gsp.Value) > 0 {
		var ar struct {
			Value []struct {
				PrincipalID string `json:"principalId"`
				AppRoleID   string `json:"appRoleId"`
			} `json:"value"`
		}
		if err := c.graphGetJSON(ctx, "/servicePrincipals/"+gsp.Value[0].ID+"/appRoleAssignedTo", &ar); err == nil {
			for _, a := range ar.Value {
				if a.PrincipalID == "" {
					continue
				}
				principals[a.PrincipalID] = true
				s.emit(model.Fact{Kind: "entra_app_role", Source: a.PrincipalID,
					Attributes: map[string]any{"appRoleId": strings.ToLower(a.AppRoleID)}})
				n++
			}
		}
	}
	// service-principal OWNERS: an owner can add a credential to the SP and impersonate it.
	// appId -> SP objectId, so APPLICATION-object owners (below) map to the SP they authenticate as.
	appIDToSP := map[string]string{}
	var sps struct {
		Value []struct {
			ID     string           `json:"id"`
			AppID  string           `json:"appId"`
			Owners []map[string]any `json:"owners"`
		} `json:"value"`
	}
	if err := c.graphGetJSON(ctx, "/servicePrincipals?$select=id,appId&$expand=owners($select=id)", &sps); err == nil {
		for _, sp := range sps.Value {
			if sp.AppID != "" {
				appIDToSP[strings.ToLower(sp.AppID)] = sp.ID
			}
			for _, o := range sp.Owners {
				oid := str(o["id"])
				if oid == "" || sp.ID == "" {
					continue
				}
				principals[oid] = true
				s.emit(model.Fact{Kind: "entra_owner", Source: oid, Target: sp.ID})
				n++
			}
		}
	}
	// APPLICATION-object OWNERS: an app owner can add a credential to the app registration,
	// which its service principal authenticates with — so map the owner to that SP.
	var apps struct {
		Value []struct {
			AppID  string           `json:"appId"`
			Owners []map[string]any `json:"owners"`
		} `json:"value"`
	}
	if err := c.graphGetJSON(ctx, "/applications?$select=appId&$expand=owners($select=id)", &apps); err == nil {
		for _, app := range apps.Value {
			spID := appIDToSP[strings.ToLower(app.AppID)]
			if spID == "" {
				continue
			}
			for _, o := range app.Owners {
				oid := str(o["id"])
				if oid == "" {
					continue
				}
				principals[oid] = true
				s.emit(model.Fact{Kind: "entra_owner", Source: oid, Target: spID})
				n++
			}
		}
	}
	// GROUP OWNERS: an owner can add itself to the group and inherit whatever the group is
	// assigned (a role-assignable group holding a privileged role => takeover).
	var groups struct {
		Value []struct {
			ID     string           `json:"id"`
			Owners []map[string]any `json:"owners"`
		} `json:"value"`
	}
	if err := c.graphGetJSON(ctx, "/groups?$select=id&$expand=owners($select=id)", &groups); err == nil {
		for _, g := range groups.Value {
			for _, o := range g.Owners {
				oid := str(o["id"])
				if oid == "" || g.ID == "" {
					continue
				}
				principals[oid] = true
				s.emit(model.Fact{Kind: "entra_group_owner", Source: oid, Target: g.ID})
				n++
			}
		}
	}
	// PIM ELIGIBLE directory-role assignments: a principal eligible for a role is one
	// self-activation away from holding it (CONDITIONAL in the engine).
	var elig struct {
		Value []struct {
			PrincipalID      string `json:"principalId"`
			RoleDefinitionID string `json:"roleDefinitionId"`
		} `json:"value"`
	}
	if err := c.graphGetJSON(ctx, "/roleManagement/directory/roleEligibilityScheduleInstances", &elig); err == nil {
		for _, r := range elig.Value {
			if r.PrincipalID == "" {
				continue
			}
			principals[r.PrincipalID] = true
			s.emit(model.Fact{Kind: "entra_role_eligible", Source: r.PrincipalID,
				Attributes: map[string]any{"roleTemplateId": strings.ToLower(r.RoleDefinitionID)}})
			n++
		}
	}
	return n, nil
}

// collectManagementGroups collects the MG -> child (MG|subscription) tree so MG-scoped
// role assignments reach exactly the subscriptions under that MG (not "all in view").
func (c *Client) collectManagementGroups(ctx context.Context, s *factSink) (int, error) {
	var list struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := c.armGetJSON(ctx, "/providers/Microsoft.Management/managementGroups?api-version=2020-05-01", &list); err != nil {
		return 0, err
	}
	n := 0
	for _, mg := range list.Value {
		var det struct {
			Properties struct {
				Children []struct {
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"children"`
			} `json:"properties"`
		}
		if c.armGetJSON(ctx, "/providers/Microsoft.Management/managementGroups/"+mg.Name+"?$expand=children&api-version=2020-05-01", &det) != nil {
			continue
		}
		for _, ch := range det.Properties.Children {
			childType := "managementGroup"
			if strings.Contains(strings.ToLower(ch.Type), "subscription") {
				childType = "subscription"
			}
			s.emit(model.Fact{Kind: "mg_hierarchy", Source: mg.Name, Target: ch.Name,
				Attributes: map[string]any{"childType": childType}})
			n++
		}
	}
	return n, nil
}

// collectPublicContainers confirms which public-access-permitting storage accounts ACTUALLY
// have a public container (publicAccess != None) — upgrading a "permits" finding to confirmed.
func (c *Client) collectPublicContainers(ctx context.Context, s *factSink) (int, error) {
	rows, err := c.argQuery(ctx, "Resources | where type =~ 'microsoft.storage/storageaccounts' "+
		"and properties.allowBlobPublicAccess == true | project id")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		id := str(r["id"])
		if id == "" {
			continue
		}
		var conts struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					PublicAccess string `json:"publicAccess"`
				} `json:"properties"`
			} `json:"value"`
		}
		if c.armGetJSON(ctx, id+"/blobServices/default/containers?api-version=2023-01-01", &conts) != nil {
			continue
		}
		for _, ct := range conts.Value {
			if pa := ct.Properties.PublicAccess; pa != "" && !strings.EqualFold(pa, "None") {
				s.emit(model.Fact{Kind: "public_container", Source: id,
					Attributes: map[string]any{"container": ct.Name, "access": pa}})
				n++
			}
		}
	}
	return n, nil
}

// resolvePrincipals batches Graph directoryObjects/getByIds to label principal GUIDs,
// and expands group memberships into member_of facts.
func (c *Client) resolvePrincipals(ctx context.Context, s *factSink, principals map[string]bool) int {
	ids := make([]string, 0, len(principals))
	for id := range principals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	n := 0
	groups := []string{}
	for i := 0; i < len(ids); i += 900 {
		end := i + 900
		if end > len(ids) {
			end = len(ids)
		}
		body, _ := json.Marshal(map[string]any{"ids": ids[i:end]})
		raw, err := c.do(ctx, http.MethodPost, graphBase+"/directoryObjects/getByIds", graphScope, body)
		if err != nil {
			continue // best-effort labeling
		}
		var resp struct {
			Value []map[string]any `json:"value"`
		}
		if json.Unmarshal(raw, &resp) != nil {
			continue
		}
		for _, o := range resp.Value {
			id := str(o["id"])
			otype := str(o["@odata.type"])
			s.emit(model.Fact{Kind: "principal", Source: id,
				Attributes: map[string]any{
					"displayName": str(o["displayName"]),
					"type":        odataType(otype),
					"appId":       str(o["appId"]),
					"upn":         str(o["userPrincipalName"]),
				}})
			n++
			if odataType(otype) == "Group" {
				groups = append(groups, id)
			}
		}
	}
	// expand group memberships (direct + transitive) into member_of facts.
	for _, g := range groups {
		var resp struct {
			Value []map[string]any `json:"value"`
		}
		if c.graphGetJSON(ctx, "/groups/"+g+"/transitiveMembers?$select=id", &resp) != nil {
			continue
		}
		for _, m := range resp.Value {
			if mid := str(m["id"]); mid != "" {
				s.emit(model.Fact{Kind: "member_of", Source: mid, Target: g})
				n++
			}
		}
	}
	return n
}

func runAzFact(led *ledger.Ledger, account, resourceType string, fn func() (int, error)) {
	scope := model.Scope{Provider: "azure", Account: account, Global: true}
	id := "global/" + resourceType
	led.Plan(id, scope, resourceType, resourceType)
	led.Start(id)
	n, err := fn()
	if err != nil {
		switch Classify(err) {
		case "denied":
			led.Finish(id, model.OutcomeDenied, n, shortErr(err))
		case "throttled":
			led.Finish(id, model.OutcomeThrottled, n, shortErr(err))
		default:
			led.Finish(id, model.OutcomeError, n, shortErr(err))
		}
		return
	}
	if n == 0 {
		led.Finish(id, model.OutcomeEmpty, 0, "")
	} else {
		led.Finish(id, model.OutcomeOK, n, "")
	}
}

// --- record helpers ---

func propMap(r map[string]any) map[string]any {
	if p, ok := r["properties"].(map[string]any); ok {
		return p
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func strSlice(v any) []string {
	var out []string
	for _, e := range asSlice(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func odataType(t string) string {
	switch t {
	case "#microsoft.graph.user":
		return "User"
	case "#microsoft.graph.group":
		return "Group"
	case "#microsoft.graph.servicePrincipal":
		return "ServicePrincipal"
	case "#microsoft.graph.application":
		return "Application"
	default:
		return "DirectoryObject"
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
