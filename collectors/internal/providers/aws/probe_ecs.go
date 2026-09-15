package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:ecs:cluster", fetchECSListTagsForResource)
}

// Exposure probe: aws-ecs-resource-tags-value-config (ListTagsForResource -> tags[].value).
func fetchECSListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ecs.NewFromConfig(c.cfg).ListTagsForResource(ctx, &ecs.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *ecs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
