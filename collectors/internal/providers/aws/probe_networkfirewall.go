package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:networkfirewall:firewall", fetchNetworkFirewallListTagsForResource)
}

// Exposure probe: aws-networkfirewall-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchNetworkFirewallListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := networkfirewall.NewFromConfig(c.cfg).ListTagsForResource(ctx, &networkfirewall.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *networkfirewall.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
