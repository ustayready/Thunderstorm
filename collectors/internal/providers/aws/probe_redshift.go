package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

func init() {
	registerFetcher("DescribeTags", "aws:redshift:cluster", fetchRedshiftDescribeTags)
}

// Exposure probe: aws-redshift-resource-tags-value-config (DescribeTags -> TaggedResources[].Tag.Value).
func fetchRedshiftDescribeTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := redshift.NewFromConfig(c.cfg).DescribeTags(ctx, &redshift.DescribeTagsInput{
		ResourceName: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *redshift.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
