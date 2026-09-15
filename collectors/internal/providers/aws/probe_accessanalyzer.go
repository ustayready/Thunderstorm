package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:accessanalyzer:analyzer", fetchAccessAnalyzerListTagsForResource)
}

// Exposure probe: aws-accessanalyzer-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchAccessAnalyzerListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := accessanalyzer.NewFromConfig(c.cfg).ListTagsForResource(ctx, &accessanalyzer.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *accessanalyzer.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
