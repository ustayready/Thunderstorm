package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:fsx:file_system", fetchFsxListTagsForResource)
}

// Exposure probe: aws-fsx-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchFsxListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := fsx.NewFromConfig(c.cfg).ListTagsForResource(ctx, &fsx.ListTagsForResourceInput{
		ResourceARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *fsx.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
