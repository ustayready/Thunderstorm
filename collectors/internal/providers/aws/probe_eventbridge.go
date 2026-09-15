package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:eventbridge:event_bus", fetchEventBridgeListTagsForResource)
}

// Exposure probe: aws-eventbridge-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchEventBridgeListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := eventbridge.NewFromConfig(c.cfg).ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{
		ResourceARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *eventbridge.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
