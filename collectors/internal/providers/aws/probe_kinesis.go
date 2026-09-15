package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

func init() {
	registerFetcher("ListTagsForStream", "aws:kinesis:stream", fetchKinesisListTagsForStream)
}

// Exposure probe: aws-kinesis-stream-tags-value-config (ListTagsForStream -> Tags[].Value).
func fetchKinesisListTagsForStream(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := kinesis.NewFromConfig(c.cfg).ListTagsForStream(ctx, &kinesis.ListTagsForStreamInput{
		StreamName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *kinesis.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
