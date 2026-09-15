package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Record is one collected item (parity with the GCP invoker).
type Record = map[string]any

// Invoke is the scheduler.Invoker entry point. Azure ops are virtual: their name
// encodes HOW to fetch, so one generic path serves every service.
//
//	arg:<azureType>     -> Azure Resource Graph list of that resource type (all subs)
//	arg-auth:<kind>     -> ARG authorizationresources query (roleassignments|roledefinitions|denyassignments)
//	arm:<path>          -> ARM REST GET at the given path (detail / data-plane, {sub} filled)
//	graph:<path>        -> Microsoft Graph GET (Entra identities)
func (c *Client) Invoke(ctx context.Context, op, region string, params map[string]string) ([]Record, error) {
	switch {
	case strings.HasPrefix(op, "arg:"):
		azType := strings.TrimPrefix(op, "arg:")
		q := fmt.Sprintf("Resources | where type =~ '%s' | project id, name, type, location, "+
			"subscriptionId, resourceGroup, kind, identity, sku, tags, properties", azType)
		return c.argQuery(ctx, q)
	case strings.HasPrefix(op, "arg-raw:"):
		return c.argQuery(ctx, strings.TrimPrefix(op, "arg-raw:"))
	case strings.HasPrefix(op, "arg-auth:"):
		kind := strings.TrimPrefix(op, "arg-auth:")
		q := fmt.Sprintf("AuthorizationResources | where type =~ 'microsoft.authorization/%s' "+
			"| project id, name, type, subscriptionId, resourceGroup, properties", kind)
		// Role DEFINITIONS are tenant-scoped in ARG and are only returned by an UNSCOPED
		// query (no subscriptions filter); assignments/denies are per-subscription.
		return c.argQueryScoped(ctx, q, kind != "roledefinitions")
	case strings.HasPrefix(op, "arm:"):
		path := strings.TrimPrefix(op, "arm:")
		for k, v := range params {
			path = strings.ReplaceAll(path, "{"+k+"}", v)
		}
		return c.armList(ctx, path)
	case strings.HasPrefix(op, "graph:"):
		path := strings.TrimPrefix(op, "graph:")
		for k, v := range params {
			path = strings.ReplaceAll(path, "{"+k+"}", v)
		}
		return c.graphList(ctx, path)
	}
	return nil, fmt.Errorf("azure: unknown op %q", op)
}

// armPost does an ARM POST (empty body) at the given path — used for listKeys-style
// credential-fetch operations that return account keys.
func (c *Client) armPost(ctx context.Context, path string) (Record, error) {
	body, err := c.do(ctx, http.MethodPost, armBase+path, armScope, []byte("{}"))
	if err != nil {
		return nil, err
	}
	var out Record
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// vaultGet does a Key Vault DATA-PLANE GET (audience https://vault.azure.net) against a
// vault's own hostname (properties.vaultUri).
func (c *Client) vaultGet(ctx context.Context, url string, v any) error {
	body, err := c.do(ctx, http.MethodGet, url, "https://vault.azure.net/.default", nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// HasOp reports whether the invoker can service an op (all virtual ops are generic).
func HasOp(op string) bool {
	for _, p := range []string{"arg:", "arg-raw:", "arg-auth:", "arm:", "graph:"} {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}

// argQuery runs an Azure Resource Graph KQL query across all in-scope subscriptions,
// paginating on $skipToken. Each row is tagged with __account (its subscriptionId) so
// the scheduler assigns the resource to the right subscription in a multi-sub tenant.
func (c *Client) argQuery(ctx context.Context, query string) ([]Record, error) {
	return c.argQueryScoped(ctx, query, true)
}

// argQueryScoped runs an ARG query; scoped=true restricts to the in-scope subscriptions,
// scoped=false runs tenant-wide (required for role definitions, which ARG returns only
// when no subscription filter is applied).
func (c *Client) argQueryScoped(ctx context.Context, query string, scoped bool) ([]Record, error) {
	if scoped && len(c.subs) == 0 {
		return nil, nil
	}
	var out []Record
	skip := ""
	for {
		reqFields := map[string]any{"query": query, "options": argOptions(skip)}
		if scoped {
			reqFields["subscriptions"] = c.subs
		}
		reqBody, _ := json.Marshal(reqFields)
		body, err := c.do(ctx, http.MethodPost,
			armBase+"/providers/Microsoft.ResourceGraph/resources?api-version="+argAPIVersion,
			armScope, reqBody)
		if err != nil {
			return out, err
		}
		var resp struct {
			Data      []Record `json:"data"`
			SkipToken string   `json:"$skipToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return out, err
		}
		for _, row := range resp.Data {
			if sub, ok := row["subscriptionId"].(string); ok && sub != "" {
				row["__account"] = sub
			}
			out = append(out, row)
		}
		if resp.SkipToken == "" {
			break
		}
		skip = resp.SkipToken
	}
	return out, nil
}

func argOptions(skip string) map[string]any {
	o := map[string]any{"resultFormat": "objectArray", "$top": 1000}
	if skip != "" {
		o["$skipToken"] = skip
	}
	return o
}

// armList does an ARM GET and returns its `value` array (or the object itself as a
// single record for a get). Follows nextLink pagination.
func (c *Client) armList(ctx context.Context, path string) ([]Record, error) {
	url := armBase + path
	var out []Record
	for url != "" {
		body, err := c.do(ctx, http.MethodGet, url, armScope, nil)
		if err != nil {
			return out, err
		}
		var env struct {
			Value    []Record `json:"value"`
			NextLink string   `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return out, err
		}
		if env.Value == nil {
			// single-object response
			var one Record
			if json.Unmarshal(body, &one) == nil && len(one) > 0 {
				out = append(out, one)
			}
			return out, nil
		}
		out = append(out, env.Value...)
		url = env.NextLink
	}
	return out, nil
}

// graphList does a Microsoft Graph GET and returns its `value` array, following
// @odata.nextLink pagination.
func (c *Client) graphList(ctx context.Context, path string) ([]Record, error) {
	full := graphBase + path
	var out []Record
	for full != "" {
		body, err := c.do(ctx, http.MethodGet, full, graphScope, nil)
		if err != nil {
			return out, err
		}
		var env struct {
			Value    []Record `json:"value"`
			NextLink string   `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return out, err
		}
		out = append(out, env.Value...)
		full = env.NextLink
	}
	return out, nil
}
