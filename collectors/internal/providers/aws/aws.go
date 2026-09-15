// Package aws is the AWS provider adapter: auth via the SDK default credential
// chain, caller identity, and opt-in-aware region discovery. Read-only.
package aws

import (
	"context"
	"fmt"

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

const optNotOptedIn = "not-opted-in"
