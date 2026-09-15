package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	registerFetcher("DescribeTags", "aws:tgw:transit-gateway", fetchTgwDescribeTags)
}

// Exposure probe: aws-tgw-resource-tags-value-config (DescribeTags -> Tags[].Value).
func fetchTgwDescribeTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ec2.NewFromConfig(c.cfg).DescribeTags(ctx, &ec2.DescribeTagsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{itemStr(item, "native_id", "arn")},
			},
		},
	}, func(o *ec2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
