package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/account"
)

func init() {
	registerFetcher("GetPrimaryEmail", "aws:account:region", fetchAccountGetPrimaryEmailExt)
}

// Exposure probe: aws-account-primary-email-pii (GetPrimaryEmail -> PrimaryEmail).
// AccountId is omitted so the call targets the identity's own account (standalone context).
func fetchAccountGetPrimaryEmailExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := account.NewFromConfig(c.cfg).GetPrimaryEmail(ctx, &account.GetPrimaryEmailInput{},
		func(o *account.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
