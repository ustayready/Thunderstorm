package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
)

func init() { registerFactCollector("ram-resource-policy", "regional", collectRamPolicies) }

// collectRamPolicies emits RAM-shared resource policies as resource_policy facts
// (CrossAccountTrust surface). RAM resource shares are regional; each shared resource
// may have an IAM resource-based policy attached by RAM to grant cross-account access.
//
// The collector:
//  1. Pages through ListResources(SELF) to enumerate every resource ARN that this
//     account currently shares via RAM.
//  2. For each resource ARN calls GetResourcePolicies with that single ARN so the
//     policy can be attributed back to the correct resource ARN in the emitted fact.
//     Resources with no policy (empty Policies slice) are silently skipped.
func collectRamPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := ram.NewFromConfig(c.cfg)
	ro := func(o *ram.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := ram.NewListResourcesPaginator(svc, &ram.ListResourcesInput{
		ResourceOwner: ramtypes.ResourceOwnerSelf,
	})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, r := range out.Resources {
			arn := aws.ToString(r.Arn)
			if arn == "" {
				continue
			}
			polOut, e := svc.GetResourcePolicies(ctx, &ram.GetResourcePoliciesInput{
				ResourceArns: []string{arn},
			}, ro)
			if e != nil || len(polOut.Policies) == 0 {
				continue // no policy on this resource — not an error
			}
			for _, pol := range polOut.Policies {
				if pol == "" {
					continue
				}
				s.emitFact("resource_policy", "CrossAccountTrust", scope,
					arn, "", map[string]any{"policy": pol})
			}
		}
	}
	return s.n - start, nil
}
