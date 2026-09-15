package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/detective"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:detective:graph", fetchDetectiveListTagsForResource)
}

// Exposure probe: aws-detective-resource-tags-value-config (ListTagsForResource -> Tags.<value>).
func fetchDetectiveListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := detective.NewFromConfig(c.cfg).ListTagsForResource(ctx, &detective.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *detective.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
