package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func init() {
	registerFetcher("ListUserTags", "aws:iam:user", fetchIamListUserTags)
}

// Exposure probe: aws-iam-user-tags-value-config (ListUserTags -> Tags[].Value).
func fetchIamListUserTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := iam.NewFromConfig(c.cfg).ListUserTags(ctx, &iam.ListUserTagsInput{
		UserName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *iam.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
