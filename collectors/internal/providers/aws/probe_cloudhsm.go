package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
)

func init() {
	registerFetcher("ListTags", "aws:cloudhsm:cluster", fetchCloudHSMListTags)
}

// Exposure probe: aws-cloudhsm-cluster-tags-value-config (ListTags -> TagList[].Value).
func fetchCloudHSMListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudhsmv2.NewFromConfig(c.cfg).ListTags(ctx, &cloudhsmv2.ListTagsInput{
		ResourceId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cloudhsmv2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
