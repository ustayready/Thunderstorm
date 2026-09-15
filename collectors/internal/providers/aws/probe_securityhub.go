package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:securityhub:standard", fetchSecurityHubListTagsForResource)
}

// Exposure probe: aws-securityhub-resource-tags-value-config (ListTagsForResource -> Tags.<value>).
func fetchSecurityHubListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := securityhub.NewFromConfig(c.cfg).ListTagsForResource(ctx, &securityhub.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *securityhub.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
