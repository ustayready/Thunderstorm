package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:guardduty:detector", fetchGuardDutyListTagsForResource)
}

// Exposure probe: aws-guardduty-resource-tags-value-config (ListTagsForResource -> Tags.<value>).
func fetchGuardDutyListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := guardduty.NewFromConfig(c.cfg).ListTagsForResource(ctx, &guardduty.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *guardduty.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
