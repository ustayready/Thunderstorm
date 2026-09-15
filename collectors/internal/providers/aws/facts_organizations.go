package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func init() {
	registerFactCollector("organizations-resource-policy", "global", collectOrganizationsPolicies)
}

// collectOrganizationsPolicies emits Organizations SERVICE_CONTROL_POLICY documents
// as scp facts (ServiceControlPolicy edge surface). Organizations is a global
// service; SCPs are the primary cross-account authorization boundary surface.
// A policy that cannot be described is silently skipped.
func collectOrganizationsPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := organizations.NewFromConfig(c.cfg)
	ro := func(o *organizations.Options) { o.Region = region }
	scope := s.scopeGlobal()
	start := s.n

	p := organizations.NewListPoliciesPaginator(svc, &organizations.ListPoliciesInput{
		Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, pol := range out.Policies {
			if pol.Id == nil {
				continue
			}
			desc, e := svc.DescribePolicy(ctx, &organizations.DescribePolicyInput{
				PolicyId: pol.Id,
			}, ro)
			if e != nil || desc.Policy == nil || desc.Policy.Content == nil {
				continue
			}
			src := firstNonEmpty(aws.ToString(pol.Arn), aws.ToString(pol.Id))
			s.emitFact("scp", "ServiceControlPolicy", scope, src, "",
				map[string]any{"document": aws.ToString(desc.Policy.Content)})
		}
	}
	return s.n - start, nil
}
