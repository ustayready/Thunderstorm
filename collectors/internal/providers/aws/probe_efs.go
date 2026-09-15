package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:efs:filesystem", fetchEFSListTagsForResource)
}

// Exposure probe: aws-efs-file-system-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchEFSListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := efs.NewFromConfig(c.cfg).ListTagsForResource(ctx, &efs.ListTagsForResourceInput{
		ResourceId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *efs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
