package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fms"
)

func init() {
	registerFetcher("GetPolicy", "aws:firewallmanager:policy", fetchFMSGetPolicy)
	registerFetcher("ListTagsForResource", "aws:firewallmanager:policy", fetchFMSListTagsForResource)
}

// Exposure probe: aws-firewallmanager-managed-service-data-json,
// aws-firewallmanager-policy-resource-tag-values (GetPolicy -> Policy.SecurityServicePolicyData.ManagedServiceData, Policy.ResourceTags[].Value).
func fetchFMSGetPolicy(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := fms.NewFromConfig(c.cfg).GetPolicy(ctx, &fms.GetPolicyInput{
		PolicyId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *fms.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-firewallmanager-resource-tags-value-config (ListTagsForResource -> TagList[].Value).
func fetchFMSListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := fms.NewFromConfig(c.cfg).ListTagsForResource(ctx, &fms.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *fms.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
