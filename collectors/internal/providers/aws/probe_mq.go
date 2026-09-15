package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
)

func init() {
	registerFetcher("ListTags", "aws:mq:broker", fetchMqListTags)
}

// Exposure probe: aws-mq-resource-tags-value-config (ListTags -> Tags.<value>).
func fetchMqListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := mq.NewFromConfig(c.cfg).ListTags(ctx, &mq.ListTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *mq.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
