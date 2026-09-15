package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:sso:instance", fetchSSOListTagsForResource)
}

// Exposure probe: aws-sso-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchSSOListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	instanceArn := aws.String(itemStr(item, "native_id", "arn"))
	out, err := ssoadmin.NewFromConfig(c.cfg).ListTagsForResource(ctx, &ssoadmin.ListTagsForResourceInput{
		InstanceArn: instanceArn,
		ResourceArn: instanceArn,
	}, func(o *ssoadmin.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
