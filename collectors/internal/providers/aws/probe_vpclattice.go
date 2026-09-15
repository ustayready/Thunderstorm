package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
)

func init() {
	registerFetcher("GetAuthPolicy", "aws:vpclattice:service-network", fetchVPCLatticeGetAuthPolicy)
	registerFetcher("ListTagsForResource", "aws:vpclattice:service-network", fetchVPCLatticeListTagsForResource)
}

// Exposure probe: aws-vpclattice-auth-policy-document (GetAuthPolicy -> policy).
func fetchVPCLatticeGetAuthPolicy(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := vpclattice.NewFromConfig(c.cfg).GetAuthPolicy(ctx, &vpclattice.GetAuthPolicyInput{
		ResourceIdentifier: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *vpclattice.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-vpclattice-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchVPCLatticeListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := vpclattice.NewFromConfig(c.cfg).ListTagsForResource(ctx, &vpclattice.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *vpclattice.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
