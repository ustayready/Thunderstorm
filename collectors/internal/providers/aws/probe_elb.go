package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

func init() {
	registerFetcher("DescribeTags", "aws:elb:load_balancer", fetchELBDescribeTags)
}

// Exposure probe: aws-elb-resource-tags-value-config (DescribeTags -> TagDescriptions[].Tags[].Value).
func fetchELBDescribeTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := elasticloadbalancingv2.NewFromConfig(c.cfg).DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{
		ResourceArns: []string{itemStr(item, "arn", "native_id")},
	}, func(o *elasticloadbalancingv2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
