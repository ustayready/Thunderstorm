package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/imagebuilder"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:imagebuilder:image_pipeline", fetchImagebuilderListTagsForResource)
}

// Exposure probe: aws-imagebuilder-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchImagebuilderListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := imagebuilder.NewFromConfig(c.cfg).ListTagsForResource(ctx, &imagebuilder.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *imagebuilder.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
