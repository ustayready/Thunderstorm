package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:appmesh:mesh", fetchAppMeshListTagsForResource)
}

// Exposure probe: aws-appmesh-resource-tags-value-config (ListTagsForResource -> tags[].value).
func fetchAppMeshListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := appmesh.NewFromConfig(c.cfg).ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *appmesh.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
