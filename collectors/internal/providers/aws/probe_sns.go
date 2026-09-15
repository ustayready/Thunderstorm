package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func init() {
	registerFetcher("ListSubscriptionsByTopic", "aws:sns:topic", fetchSNSListSubscriptionsByTopic)
	registerFetcher("ListTagsForResource", "aws:sns:topic", fetchSNSListTagsForResource)
}

// Exposure probe: aws-sns-subscription-endpoint-config (ListSubscriptionsByTopic -> Subscriptions[].Endpoint).
func fetchSNSListSubscriptionsByTopic(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sns.NewFromConfig(c.cfg).ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{
		TopicArn: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sns.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-sns-topic-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchSNSListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sns.NewFromConfig(c.cfg).ListTagsForResource(ctx, &sns.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *sns.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
