// Package azure is the Azure provider adapter: auth via azidentity
// (DefaultAzureCredential — picks up the `az` login / managed identity / env), caller
// identity, subscription discovery, and a GENERIC layer over Azure Resource Graph (ARG)
// + ARM REST. Like GCP (uniform REST), one authenticated HTTP path serves every service:
// inventory is a single ARG KQL query per resource type, RBAC facts come from ARG's
// authorizationresources, and identities come from Microsoft Graph. Read-only.
package azure

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	armBase       = "https://management.azure.com"
	graphBase     = "https://graph.microsoft.com/v1.0"
	armScope      = "https://management.azure.com/.default"
	graphScope    = "https://graph.microsoft.com/.default"
	argAPIVersion = "2021-03-01"
)

// Client wraps the credential + resolved tenant/subscription context.
type Client struct {
	cred    azcore.TokenCredential
	httpc   *http.Client
	tenant  string
	subs    []string // all subscriptions in scope for this scan
	primary string   // the primary/first subscription id (bundle account)
	caller  string   // caller upn / app id — the default foothold
	blobDir string
}

// Load builds an Azure client from DefaultAzureCredential. subscription (optional)
// restricts the scan to one subscription; empty means all accessible subscriptions.
func Load(ctx context.Context, subscription string) (*Client, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure auth (is `az login` done, or a credential set?): %w", err)
	}
	c := &Client{cred: cred, httpc: &http.Client{Timeout: 90 * time.Second}}
	// resolve caller + tenant + subscriptions from the ARM token and the subscriptions API.
	if err := c.resolve(ctx, subscription); err != nil {
		return nil, err
	}
	return c, nil
}

// Primary returns the primary subscription id (the bundle "account").
func (c *Client) Primary() string { return c.primary }

// Subscriptions returns every subscription in scope.
func (c *Client) Subscriptions() []string { return c.subs }

// SetBlobDir sets where large downloads would be stored (parity with AWS/GCP).
func (c *Client) SetBlobDir(dir string) { c.blobDir = dir }

// Identity is the caller-identity smoke-test result (the sts analog).
type Identity struct {
	Account string // primary subscription id — the bundle scope
	Email   string // caller upn / app id — the default foothold
	Tenant  string
}

// CallerIdentity returns the resolved caller (already fetched in Load).
func (c *Client) CallerIdentity(ctx context.Context) (Identity, error) {
	if c.primary == "" {
		return Identity{}, fmt.Errorf("no accessible subscriptions for this identity")
	}
	return Identity{Account: c.primary, Email: c.caller, Tenant: c.tenant}, nil
}

// resolve discovers the caller (from token claims), tenant, and subscriptions.
func (c *Client) resolve(ctx context.Context, subscription string) error {
	tok, err := c.token(ctx, armScope)
	if err != nil {
		return fmt.Errorf("acquiring ARM token: %w", err)
	}
	c.caller, c.tenant = callerFromJWT(tok)

	var out struct {
		Value []struct {
			SubscriptionID string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
			State          string `json:"state"`
			TenantID       string `json:"tenantId"`
		} `json:"value"`
	}
	if err := c.armGetJSON(ctx, "/subscriptions?api-version=2022-12-01", &out); err != nil {
		return fmt.Errorf("listing subscriptions: %w", err)
	}
	for _, s := range out.Value {
		if s.State != "Enabled" {
			continue
		}
		if subscription != "" && !strings.EqualFold(s.SubscriptionID, subscription) {
			continue
		}
		c.subs = append(c.subs, s.SubscriptionID)
		if c.tenant == "" {
			c.tenant = s.TenantID
		}
	}
	if len(c.subs) > 0 {
		c.primary = c.subs[0]
	}
	return nil
}

// token fetches an access token for the given scope (audience).
func (c *Client) token(ctx context.Context, scope string) (string, error) {
	at, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", err
	}
	return at.Token, nil
}

// callerFromJWT extracts the caller principal + tenant from an access-token JWT
// (upn for users, appid/app_displayname for service principals). Best-effort; the
// token is already validated by Azure — we only read claims, never trust for authz.
func callerFromJWT(tok string) (caller, tenant string) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c struct {
		UPN      string `json:"upn"`
		Unique   string `json:"unique_name"`
		Email    string `json:"email"`
		AppID    string `json:"appid"`
		AppName  string `json:"app_displayname"`
		OID      string `json:"oid"`
		TenantID string `json:"tid"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return "", ""
	}
	caller = firstNonEmpty(c.UPN, c.Unique, c.Email, c.AppName, c.AppID, c.OID)
	return caller, c.TenantID
}

// Classify maps an Azure error to the ledger outcome vocabulary.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "403") || strings.Contains(s, "Authorization") ||
		strings.Contains(s, "Forbidden") || strings.Contains(s, "AuthorizationFailed"):
		return "denied"
	case strings.Contains(s, "429") || strings.Contains(s, "TooManyRequests") ||
		strings.Contains(s, "throttl") || strings.Contains(s, "quota"):
		return "throttled"
	case strings.Contains(s, "not registered") || strings.Contains(s, "SubscriptionNotRegistered") ||
		strings.Contains(s, "NoRegisteredProviderFound") || strings.Contains(s, "DisallowedProvider"):
		return "disabled"
	default:
		return "error"
	}
}

// --- HTTP helpers ---

func (c *Client) armGetJSON(ctx context.Context, path string, v any) error {
	body, err := c.do(ctx, http.MethodGet, armBase+path, armScope, nil)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(body, v)
}

// graphGetJSON does an authenticated Microsoft Graph GET.
func (c *Client) graphGetJSON(ctx context.Context, path string, v any) error {
	body, err := c.do(ctx, http.MethodGet, graphBase+path, graphScope, nil)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(body, v)
}

// do performs an authenticated request for the given audience scope and returns the
// body, turning non-2xx into errors carrying the Azure error code for Classify.
func (c *Client) do(ctx context.Context, method, url, scope string, reqBody []byte) ([]byte, error) {
	tok, err := c.token(ctx, scope)
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if reqBody != nil {
		r = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: %d %s", method, redactURL(url), resp.StatusCode, azErrMessage(body))
	}
	return body, nil
}

func azErrMessage(body []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && (e.Error.Code != "" || e.Error.Message != "") {
		return strings.TrimSpace(e.Error.Code + ": " + e.Error.Message)
	}
	if len(body) > 200 {
		return string(body[:200])
	}
	return string(body)
}

func redactURL(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
