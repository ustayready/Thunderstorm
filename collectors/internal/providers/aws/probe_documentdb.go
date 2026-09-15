package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:documentdb:db_cluster", fetchDocumentDBListTagsForResource)
}

// Exposure probe: aws-documentdb-resource-tags-value-config (ListTagsForResource -> TagList[].Value).
func fetchDocumentDBListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := rds.NewFromConfig(c.cfg).ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
		ResourceName: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *rds.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
