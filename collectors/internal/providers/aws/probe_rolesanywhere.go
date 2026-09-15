package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:rolesanywhere:trust-anchor", fetchRolesAnywhereListTagsForResource)
}

// Exposure probe: aws-rolesanywhere-resource-tags-value-config (ListTagsForResource -> tags[].value).
func fetchRolesAnywhereListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := rolesanywhere.NewFromConfig(c.cfg).ListTagsForResource(ctx, &rolesanywhere.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *rolesanywhere.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
