package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:bedrock:custom_model", fetchBedrockListTagsForResource)
}

// Exposure probe: aws-bedrock-resource-tags-value-config (ListTagsForResource -> tags[].value).
func fetchBedrockListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := bedrock.NewFromConfig(c.cfg).ListTagsForResource(ctx, &bedrock.ListTagsForResourceInput{
		ResourceARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *bedrock.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
