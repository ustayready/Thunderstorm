package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
)

func init() {
	registerFetcher("ListTags", "aws:memorydb:cluster", fetchMemoryDBListTags)
}

// Exposure probe: aws-memorydb-resource-tags-value-config (ListTags -> TagList[].Value).
func fetchMemoryDBListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := memorydb.NewFromConfig(c.cfg).ListTags(ctx, &memorydb.ListTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *memorydb.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
