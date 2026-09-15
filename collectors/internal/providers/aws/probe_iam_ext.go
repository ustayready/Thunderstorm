package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func init() {
	registerFetcher("ListRoleTags", "aws:iam:role", fetchIamListRoleTagsExt)
}

// fetchIamListRoleTagsExt implements the exposure probe for
// aws-iam-role-tags-value-config (ListRoleTags -> Tags[].Value).
// Role tag values are customer-controlled plaintext and can inadvertently
// contain credentials, API tokens, or other sensitive identifiers.
func fetchIamListRoleTagsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	roleName := itemStr(item, "native_id", "arn")
	out, err := iam.NewFromConfig(c.cfg).ListRoleTags(ctx, &iam.ListRoleTagsInput{
		RoleName: aws.String(roleName),
	}, func(o *iam.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
