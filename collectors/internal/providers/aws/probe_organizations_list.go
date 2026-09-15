package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func init() {
	registerListFetcher("DescribePolicy", listFetchOrganizationsDescribePolicy)
}

// listFetchOrganizationsDescribePolicy enumerates every Organizations policy
// across all supported policy types and returns each DescribePolicy detail
// response (read-only). The prober applies the site's response_path
// (Policy.Content) to each returned item.
func listFetchOrganizationsDescribePolicy(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := organizations.NewFromConfig(c.cfg)
	ro := func(o *organizations.Options) { o.Region = region }

	policyTypes := types.PolicyType("").Values()

	var out []any
	for _, pt := range policyTypes {
		p := organizations.NewListPoliciesPaginator(svc, &organizations.ListPoliciesInput{
			Filter: pt,
		})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx, ro)
			if err != nil {
				// A policy type may not be enabled in this org — skip gracefully.
				break
			}
			for _, summary := range page.Policies {
				if summary.Id == nil {
					continue
				}
				d, e := svc.DescribePolicy(ctx, &organizations.DescribePolicyInput{
					PolicyId: aws.String(*summary.Id),
				}, ro)
				if e != nil {
					continue // per-item error (not found / access) — skip
				}
				out = append(out, jsonify(d))
			}
		}
	}
	return out, nil
}
