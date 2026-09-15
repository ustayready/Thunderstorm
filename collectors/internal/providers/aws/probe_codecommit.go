package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:codecommit:repository", fetchCodecommitListTagsForResource)
}

// Exposure probe: aws-codecommit-repository-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchCodecommitListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codecommit.NewFromConfig(c.cfg).ListTagsForResource(ctx, &codecommit.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *codecommit.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
