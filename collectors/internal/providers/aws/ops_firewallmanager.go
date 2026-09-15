package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fms"
)

func init() { register("firewallmanager:ListPolicies", opFirewallManagerListPolicies) }

// opFirewallManagerListPolicies enumerates Firewall Manager policies (read-only).
func opFirewallManagerListPolicies(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := fms.NewFromConfig(c.cfg)
	p := fms.NewListPoliciesPaginator(svc, &fms.ListPoliciesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *fms.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, pol := range out.PolicyList {
			recs = append(recs, Record{
				"policy_id":  aws.ToString(pol.PolicyId),
				"policy_arn": aws.ToString(pol.PolicyArn),
			})
		}
	}
	return recs, nil
}
