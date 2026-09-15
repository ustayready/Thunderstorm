package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:ds:directory", fetchDsListTagsForResource)
}

// Exposure probe: aws-ds-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchDsListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := directoryservice.NewFromConfig(c.cfg).ListTagsForResource(ctx, &directoryservice.ListTagsForResourceInput{
		ResourceId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *directoryservice.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
