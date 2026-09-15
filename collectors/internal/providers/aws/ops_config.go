package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

func init() { register("config:DescribeConfigRules", opConfigDescribeConfigRules) }

// opConfigDescribeConfigRules enumerates AWS Config rules (read-only).
func opConfigDescribeConfigRules(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := configservice.NewFromConfig(c.cfg)
	p := configservice.NewDescribeConfigRulesPaginator(svc, &configservice.DescribeConfigRulesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *configservice.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, r := range out.ConfigRules {
			recs = append(recs, Record{
				"config_rule_name": aws.ToString(r.ConfigRuleName),
				"config_rule_arn":  aws.ToString(r.ConfigRuleArn),
			})
		}
	}
	return recs, nil
}
