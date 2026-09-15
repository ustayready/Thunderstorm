package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:macie:classification-job", fetchMacieListTagsForResource)
}

// Exposure probe: aws-macie-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchMacieListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := macie2.NewFromConfig(c.cfg).ListTagsForResource(ctx, &macie2.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *macie2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
