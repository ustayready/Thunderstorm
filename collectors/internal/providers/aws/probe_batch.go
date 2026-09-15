package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:batch:job-queue", fetchBatchListTagsForResource)
}

// Exposure probe: aws-batch-job-definition-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchBatchListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := batch.NewFromConfig(c.cfg).ListTagsForResource(ctx, &batch.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *batch.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
