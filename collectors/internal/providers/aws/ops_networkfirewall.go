package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
)

func init() { register("network-firewall:ListFirewalls", opNetworkFirewallListFirewalls) }

// opNetworkFirewallListFirewalls enumerates Network Firewall firewalls (read-only).
func opNetworkFirewallListFirewalls(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := networkfirewall.NewFromConfig(c.cfg)
	p := networkfirewall.NewListFirewallsPaginator(svc, &networkfirewall.ListFirewallsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *networkfirewall.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, fw := range out.Firewalls {
			recs = append(recs, Record{
				"firewall_name": aws.ToString(fw.FirewallName),
				"firewall_arn":  aws.ToString(fw.FirewallArn),
			})
		}
	}
	return recs, nil
}
