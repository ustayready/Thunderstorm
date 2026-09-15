package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/qldb"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:qldb:ledger", fetchQldbListTagsForResource)
}

// Exposure probe: aws-qldb-ledger-tags-value-config (ListTagsForResource -> Tags.<value>).
func fetchQldbListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := qldb.NewFromConfig(c.cfg).ListTagsForResource(ctx, &qldb.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *qldb.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
