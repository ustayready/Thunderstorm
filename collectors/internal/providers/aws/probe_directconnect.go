package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/directconnect"
)

func init() {
	registerFetcher("DescribeTags", "aws:directconnect:connection", fetchDirectconnectDescribeTags)
}

// Exposure probe: aws-directconnect-resource-tags-value-config (DescribeTags -> resourceTags[].tags[].value).
func fetchDirectconnectDescribeTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := directconnect.NewFromConfig(c.cfg).DescribeTags(ctx, &directconnect.DescribeTagsInput{
		ResourceArns: []string{itemStr(item, "arn", "native_id")},
	}, func(o *directconnect.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
