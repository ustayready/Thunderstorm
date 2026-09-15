package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

func init() {
	registerFetcher("ListTags", "aws:sagemaker:notebook-instance", fetchSageMakerListTags)
}

// Exposure probe: aws-sagemaker-resource-tags-value-config (ListTags -> Tags[].Value).
func fetchSageMakerListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).ListTags(ctx, &sagemaker.ListTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
