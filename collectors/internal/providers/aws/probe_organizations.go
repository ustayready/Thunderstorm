package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

func init() {
	registerFetcher("DescribeAccount", "aws:organizations:account", fetchOrganizationsDescribeAccount)
	registerFetcher("ListTagsForResource", "aws:organizations:account", fetchOrganizationsListTagsForResource)
}

// Exposure probe: aws-organizations-account-email-pii (DescribeAccount -> Account.Email).
func fetchOrganizationsDescribeAccount(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := organizations.NewFromConfig(c.cfg).DescribeAccount(ctx, &organizations.DescribeAccountInput{
		AccountId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *organizations.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-organizations-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchOrganizationsListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := organizations.NewFromConfig(c.cfg).ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{
		ResourceId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *organizations.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
