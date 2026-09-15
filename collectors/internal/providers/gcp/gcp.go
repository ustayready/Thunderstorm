// Package gcp is the GCP provider adapter: auth via Application Default
// Credentials, caller identity, project/location scope discovery, and a GENERIC
// REST invoker. Unlike AWS (typed SDK per service), GCP's APIs are uniform REST,
// so one authenticated HTTP path serves every service — inventory and exposure
// are driven by a data table of endpoint specs (endpoints.go). Read-only.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// cloudPlatformScope is the read scope covering every GCP API we call.
const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// Client wraps an authenticated HTTP client + the project/impersonation context.
type Client struct {
	httpc    *http.Client
	project  string
	blobDir  string
	authDesc string // non-identifying description of the active credential (no email/keys)
}

// Load builds a GCP client from Application Default Credentials (env
// GOOGLE_APPLICATION_CREDENTIALS, gcloud user ADC, metadata server, or workload
// identity). project is the target project. If impersonateSA is set, the whole run
// acts AS that service account: the base ADC identity impersonates it via IAM
// Credentials (the base identity must hold roles/iam.serviceAccountTokenCreator on
// the target SA). CallerIdentity then resolves to the impersonated SA, so the
// engagement's foothold is the SA rather than the base login.
func Load(ctx context.Context, project, impersonateSA string) (*Client, error) {
	if project == "" {
		return nil, fmt.Errorf("gcp requires --project")
	}
	creds, err := google.FindDefaultCredentials(ctx, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("loading application default credentials: %w", err)
	}
	ts := creds.TokenSource
	// Non-identifying descriptor of what auth is actually in effect, so you can tell
	// whether an SA key was picked up WITHOUT the email/key ever appearing in output.
	gac := "unset"
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		gac = "set"
	}
	base := credentialType(creds.JSON)
	authDesc := fmt.Sprintf("base credentials = %s (GOOGLE_APPLICATION_CREDENTIALS=%s)", base, gac)
	if impersonateSA != "" {
		// ReuseTokenSource caches the minted token and refreshes it before expiry.
		ts = oauth2.ReuseTokenSource(nil, &impersonatedTokenSource{
			ctx: ctx, base: creds.TokenSource, target: impersonateSA,
		})
		authDesc = fmt.Sprintf("impersonating a target service account via %s base creds (GOOGLE_APPLICATION_CREDENTIALS=%s)", base, gac)
	}
	httpc := oauth2.NewClient(ctx, ts)
	httpc.Timeout = 60 * time.Second
	return &Client{httpc: httpc, project: project, authDesc: authDesc}, nil
}

// AuthDescriptor returns a non-identifying summary of the active credential — its
// type and whether GOOGLE_APPLICATION_CREDENTIALS is set. Never includes an email,
// key, or token, so it is safe to print/log.
func (c *Client) AuthDescriptor() string { return c.authDesc }

// credentialType extracts the "type" field of an ADC JSON credential (service_account,
// authorized_user, external_account, impersonated_service_account). Empty JSON means
// the credential was computed (e.g. the GCE/GKE metadata server).
func credentialType(raw []byte) string {
	if len(raw) == 0 {
		return "computed/metadata"
	}
	var t struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &t) == nil && t.Type != "" {
		return t.Type
	}
	return "unknown"
}

// impersonatedTokenSource mints short-lived access tokens for a target service
// account by calling IAM Credentials generateAccessToken, authenticated with the
// caller's base ADC token. Requires roles/iam.serviceAccountTokenCreator on the
// target. Error text is deliberately identifier-free (no SA email / token in logs).
type impersonatedTokenSource struct {
	ctx    context.Context
	base   oauth2.TokenSource
	target string
}

func (t *impersonatedTokenSource) Token() (*oauth2.Token, error) {
	baseTok, err := t.base.Token()
	if err != nil {
		return nil, fmt.Errorf("base credentials for impersonation: %w", err)
	}
	url := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
		t.target + ":generateAccessToken"
	payload := `{"scope":["` + cloudPlatformScope + `"],"lifetime":"3600s"}`
	req, err := http.NewRequestWithContext(t.ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	baseTok.SetAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		// Surface status + the API's error message but NOT the target SA / token.
		return nil, fmt.Errorf("impersonation generateAccessToken failed: HTTP %d (does the base identity hold serviceAccountTokenCreator on the target SA?): %s",
			resp.StatusCode, impersonationError(data))
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing impersonation response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("impersonation returned an empty access token")
	}
	exp, _ := time.Parse(time.RFC3339, out.ExpireTime)
	return &oauth2.Token{AccessToken: out.AccessToken, TokenType: "Bearer", Expiry: exp}, nil
}

// impersonationError pulls the human-readable error.message from an IAM Credentials
// error body (e.g. "Permission 'iam.serviceAccounts.getAccessToken' denied") without
// leaking the full response.
func impersonationError(data []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return "unknown error"
}

// Project returns the target project id.
func (c *Client) Project() string { return c.project }

// DiscoverProjects lists the ACTIVE project ids the caller (ADC) can access via
// Cloud Resource Manager. Used for the multi-scope discovery default when no
// explicit --project / --gcp-projects / --scopes is supplied. Needs no target
// project — it enumerates whatever the identity is authorized to see.
func DiscoverProjects(ctx context.Context) ([]string, error) {
	creds, err := google.FindDefaultCredentials(ctx, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("loading application default credentials: %w", err)
	}
	httpc := oauth2.NewClient(ctx, creds.TokenSource)
	httpc.Timeout = 60 * time.Second
	var out []string
	pageToken := ""
	for {
		url := "https://cloudresourcemanager.googleapis.com/v1/projects?pageSize=500"
		if pageToken != "" {
			url += "&pageToken=" + pageToken
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := httpc.Do(req)
		if err != nil {
			return nil, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("cloudresourcemanager projects.list: HTTP %d: %s", resp.StatusCode, gcpErrMessage(data))
		}
		var page struct {
			Projects []struct {
				ProjectID      string `json:"projectId"`
				LifecycleState string `json:"lifecycleState"`
			} `json:"projects"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, err
		}
		for _, p := range page.Projects {
			if p.LifecycleState == "ACTIVE" {
				out = append(out, p.ProjectID)
			}
		}
		if page.NextPageToken == "" {
			break
		}
		pageToken = page.NextPageToken
	}
	return out, nil
}

// SetBlobDir sets where large downloads would be stored (parity with AWS; GCP
// does not download blobs today).
func (c *Client) SetBlobDir(dir string) { c.blobDir = dir }

// Identity is the result of the caller-identity smoke test (the sts analog).
type Identity struct {
	Account string // project id — the "account" scope for the bundle
	Email   string // caller email / SA — the default foothold
}

// CallerIdentity confirms auth works and returns the caller. Uses the OAuth2
// tokeninfo endpoint (returns the user/SA email for a valid ADC token).
func (c *Client) CallerIdentity(ctx context.Context) (Identity, error) {
	var info struct {
		Email    string `json:"email"`
		Sub      string `json:"sub"`
		Azp      string `json:"azp"`
		IssuedTo string `json:"issued_to"`
	}
	if err := c.getJSON(ctx, "https://oauth2.googleapis.com/tokeninfo", &info); err != nil {
		return Identity{}, err
	}
	email := firstNonEmpty(info.Email, info.IssuedTo, info.Azp, info.Sub)
	return Identity{Account: c.project, Email: email}, nil
}

// Location mirrors AWS Region: a location usable for regional resource collection.
type Location struct {
	Name        string
	Collectable bool
}

// Scopes discovers the location set for regional resources (Compute regions are
// the canonical GCP location list). "global" is always implied for project-level
// resources (IAM, storage buckets, secrets). Never hardcoded — the anti-"forgot a
// location" primitive. If Compute is disabled, returns an empty regional set (the
// ledger records regional resources as skipped, not errors).
func (c *Client) Scopes(ctx context.Context) ([]Location, error) {
	var out struct {
		Items []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"items"`
	}
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/regions", c.project)
	if err := c.getJSON(ctx, url, &out); err != nil {
		// Compute disabled or denied — regional resources simply won't be scoped.
		return nil, nil
	}
	var locs []Location
	for _, r := range out.Items {
		locs = append(locs, Location{Name: r.Name, Collectable: true})
	}
	return locs, nil
}

// Classify maps a GCP API error to the ledger outcome vocabulary.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "403") || strings.Contains(s, "PERMISSION_DENIED") ||
		strings.Contains(s, "forbidden") || strings.Contains(s, "IAM_PERMISSION_DENIED"):
		return "denied"
	case strings.Contains(s, "429") || strings.Contains(s, "RESOURCE_EXHAUSTED") ||
		strings.Contains(s, "rateLimitExceeded") || strings.Contains(s, "quota"):
		return "throttled"
	case strings.Contains(s, "SERVICE_DISABLED") || strings.Contains(s, "has not been used") ||
		strings.Contains(s, "is disabled"):
		return "disabled"
	default:
		return "error"
	}
}

// getJSON does an authenticated GET and unmarshals the JSON body into v.
func (c *Client) getJSON(ctx context.Context, url string, v any) error {
	body, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(body, v)
}

// do performs an authenticated request and returns the body, turning non-2xx
// responses into errors that carry the status + GCP error message for Classify.
func (c *Client) do(ctx context.Context, method, url string, reqBody io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}
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
		msg := gcpErrMessage(body)
		return nil, fmt.Errorf("%s %s: %d %s", method, redactURL(url), resp.StatusCode, msg)
	}
	return body, nil
}

// gcpErrMessage pulls the human message out of a GCP error envelope.
func gcpErrMessage(body []byte) string {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		if e.Error.Status != "" {
			return e.Error.Status + ": " + e.Error.Message
		}
		return e.Error.Message
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
