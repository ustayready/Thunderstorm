// Package aws is the AWS provider adapter: auth via the SDK default credential
// chain, caller identity, and opt-in-aware region discovery. Read-only.
package aws

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Client wraps a loaded AWS config + the profile it came from.
type Client struct {
	cfg     aws.Config
	profile string
	blobDir string // where http:GetBlob stores downloads (optional)
}

// Load builds an AWS config from the named shared-config profile (or the default
// chain when profile==""). bootstrapRegion is used for global/region-listing
// calls (AWS needs *a* region to sign).
//
// Retry is configured for high concurrency: ADAPTIVE mode adds a client-side rate
// limiter that backs off under throttling, and MaxAttempts is raised well above
// the SDK default of 3. Without this, running many fact collectors in parallel
// throttles IAM and silently drops policy documents (e.g. AdministratorAccess),
// which makes admins look like they have no permissions.
func Load(ctx context.Context, profile, bootstrapRegion string, debug bool) (*Client, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(bootstrapRegion),
		config.WithRetryMode(aws.RetryModeAdaptive),
		config.WithRetryMaxAttempts(10),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	// --debug: emit SDK-level request/response/retry wire logs (to the SDK's
	// default logger, stderr) so every HTTP call in/out is visible.
	if debug {
		opts = append(opts, config.WithClientLogMode(
			aws.LogRequest|aws.LogResponse|aws.LogRetries|aws.LogDeprecatedUsage))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading aws config: %w", err)
	}
	return &Client{cfg: cfg, profile: profile}, nil
}

// Identity is the result of sts:GetCallerIdentity.
type Identity struct {
	Account string
	UserID  string
	ARN     string
}

// CallerIdentity confirms auth works and returns the account/principal.
func (c *Client) CallerIdentity(ctx context.Context) (Identity, error) {
	out, err := sts.NewFromConfig(c.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Account: aws.ToString(out.Account),
		UserID:  aws.ToString(out.UserId),
		ARN:     aws.ToString(out.Arn),
	}, nil
}

// Region describes a region and whether it's usable for collection.
type Region struct {
	Name        string
	OptInStatus string // opt-in-not-required | opted-in | not-opted-in
	Collectable bool   // false for not-opted-in (calling it would error)
}

// Regions enumerates ALL regions with opt-in status — the anti-"forgot a region"
// primitive. not-opted-in regions are returned but marked not collectable so the
// planner records them as skipped:not_opted_in rather than erroring on them.
func (c *Client) Regions(ctx context.Context) ([]Region, error) {
	out, err := ec2.NewFromConfig(c.cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	var regions []Region
	for _, r := range out.Regions {
		status := aws.ToString(r.OptInStatus)
		regions = append(regions, Region{
			Name:        aws.ToString(r.RegionName),
			OptInStatus: status,
			Collectable: status != optNotOptedIn,
		})
	}
	return regions, nil
}

// Config exposes the loaded config for per-service clients (M1+).
func (c *Client) Config() aws.Config { return c.cfg }

// defaultEnabledRegions is the AWS commercial partition's default-enabled
// (non-opt-in) regions. It's the fallback when ec2:DescribeRegions is denied, so a
// scan keeps running instead of aborting. Opt-in regions (af-south-1, ap-east-1,
// me-*, eu-south-* and the rest), GovCloud, and China are NOT here: a caller that
// needs one of those under denied discovery has to name it with --only-regions.
var defaultEnabledRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"ca-central-1",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2",
	"sa-east-1",
}

// FallbackRegions builds a region list without calling DescribeRegions, for the
// denied-discovery path. If the caller named regions (only is non-empty) it uses
// exactly those, so an explicit set outside defaultEnabledRegions still works;
// otherwise it unions bootstrapRegion with the default commercial set. Every
// region comes back Collectable with OptInStatus "unknown". Why "unknown": nothing
// here can check opt-in status without the API, and a not-opted-in region just
// produces denied gaps downstream like any other denial.
func FallbackRegions(bootstrapRegion string, only map[string]bool) []Region {
	var names []string
	seen := map[string]bool{}
	add := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		names = append(names, n)
	}
	if len(only) > 0 {
		keys := make([]string, 0, len(only))
		for n := range only {
			keys = append(keys, n)
		}
		sort.Strings(keys)
		for _, n := range keys {
			add(n)
		}
	} else {
		add(bootstrapRegion)
		for _, n := range defaultEnabledRegions {
			add(n)
		}
	}
	regions := make([]Region, 0, len(names))
	for _, n := range names {
		regions = append(regions, Region{Name: n, OptInStatus: "unknown", Collectable: true})
	}
	return regions
}

const optNotOptedIn = "not-opted-in"
