package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func init() {
	registerFetcher("ReceiveMessage", "aws:sqs:queue", fetchSQSReceiveMessage)
	registerFetcher("GetQueueAttributes", "aws:sqs:queue", fetchSQSGetQueueAttributes)
	registerFetcher("ListQueueTags", "aws:sqs:queue", fetchSQSListQueueTags)
}

// Exposure probe: aws-sqs-message-body-content + aws-sqs-message-attribute-values
// (ReceiveMessage -> Messages[].Body / Messages[].MessageAttributes).
func fetchSQSReceiveMessage(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sqs.NewFromConfig(c.cfg).ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:              aws.String(itemStr(item, "native_id", "arn")),
		MaxNumberOfMessages:   10,
		MessageAttributeNames: []string{"All"},
	}, func(o *sqs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-sqs-queue-policy-config (GetQueueAttributes -> Attributes.Policy).
func fetchSQSGetQueueAttributes(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sqs.NewFromConfig(c.cfg).GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(itemStr(item, "native_id", "arn")),
		AttributeNames: []types.QueueAttributeName{types.QueueAttributeNamePolicy},
	}, func(o *sqs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-sqs-queue-tags-value-config (ListQueueTags -> Tags.<value>).
func fetchSQSListQueueTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sqs.NewFromConfig(c.cfg).ListQueueTags(ctx, &sqs.ListQueueTagsInput{
		QueueUrl: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sqs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
