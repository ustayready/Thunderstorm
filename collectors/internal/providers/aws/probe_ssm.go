package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:ssm:managed-instance", fetchSSMListTagsForResource)
}

// Exposure probe: aws-ssm-resource-tags-value-config (ListTagsForResource -> TagList[].Value).
func fetchSSMListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ssm.NewFromConfig(c.cfg).ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: types.ResourceTypeForTaggingManagedInstance,
		ResourceId:   aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *ssm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
