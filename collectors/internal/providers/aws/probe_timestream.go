package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:timestream:database", fetchTimestreamListTagsForResource)
}

// Exposure probe: aws-timestream-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchTimestreamListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := timestreamwrite.NewFromConfig(c.cfg).ListTagsForResource(ctx, &timestreamwrite.ListTagsForResourceInput{
		ResourceARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *timestreamwrite.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
