package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:codedeploy:application", fetchCodeDeployListTagsForResource)
}

// Exposure probe: aws-codedeploy-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchCodeDeployListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codedeploy.NewFromConfig(c.cfg).ListTagsForResource(ctx, &codedeploy.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *codedeploy.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
