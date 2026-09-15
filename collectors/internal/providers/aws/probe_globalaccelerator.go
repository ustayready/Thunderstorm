package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:globalaccelerator:accelerator", fetchGlobalacceleratorListTagsForResource)
}

// Exposure probe: aws-globalaccelerator-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchGlobalacceleratorListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := globalaccelerator.NewFromConfig(c.cfg).ListTagsForResource(ctx, &globalaccelerator.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *globalaccelerator.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
