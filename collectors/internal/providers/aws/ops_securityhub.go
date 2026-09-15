package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

func init() { register("securityhub:GetEnabledStandards", opSecurityHubGetEnabledStandards) }

// opSecurityHubGetEnabledStandards enumerates enabled Security Hub standards (read-only).
func opSecurityHubGetEnabledStandards(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := securityhub.NewFromConfig(c.cfg)
	p := securityhub.NewGetEnabledStandardsPaginator(svc, &securityhub.GetEnabledStandardsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *securityhub.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, s := range out.StandardsSubscriptions {
			recs = append(recs, Record{
				"standards_subscription_arn": aws.ToString(s.StandardsSubscriptionArn),
			})
		}
	}
	return recs, nil
}
