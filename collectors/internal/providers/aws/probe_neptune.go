package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:neptune:db_cluster", fetchNeptuneListTagsForResource)
}

// Exposure probe: aws-neptune-resource-tags-value-config (ListTagsForResource -> TagList[].Value).
func fetchNeptuneListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := neptune.NewFromConfig(c.cfg).ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{
		ResourceName: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *neptune.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
