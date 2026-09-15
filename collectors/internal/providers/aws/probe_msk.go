package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:msk:cluster", fetchMskListTagsForResource)
}

// Exposure probe: aws-msk-cluster-tags-value-config (ListTagsForResource -> Tags.<value>).
func fetchMskListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := kafka.NewFromConfig(c.cfg).ListTagsForResource(ctx, &kafka.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *kafka.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
