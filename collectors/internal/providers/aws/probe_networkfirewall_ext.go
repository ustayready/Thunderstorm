package aws

// Exposure probes for Network Firewall — additional read_api operations.
//
// The inventory resource type is aws:networkfirewall:firewall whose native_id
// is the firewall name and arn is the firewall ARN.  DescribeRuleGroup is
// keyed by rule-group ARN (a sub-resource), so the fetcher first enumerates
// all rule groups in the region via ListRuleGroups and then describes each one.
// The aggregated slice covers both YAML catalog sites:
//   - aws-networkfirewall-suricata-rules-string  (RuleGroup.RulesSource.RulesString)
//   - aws-networkfirewall-rule-variable-values   (RuleGroup.RuleVariables)

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
)

func init() {
	registerFetcher("DescribeRuleGroup", "aws:networkfirewall:firewall", fetchNetworkFirewallDescribeRuleGroupExt)
}

// fetchNetworkFirewallDescribeRuleGroupExt implements the exposure probes
// aws-networkfirewall-suricata-rules-string and
// aws-networkfirewall-rule-variable-values.
//
// Rule groups are a separate resource type from firewalls; there is no
// direct mapping from a firewall ARN to its rule groups.  Instead, the
// fetcher lists all rule groups available in the region (both STATEFUL and
// STATELESS) and calls DescribeRuleGroup on each, returning an aggregated
// list so the prober can walk every group's RulesSource and RuleVariables.
func fetchNetworkFirewallDescribeRuleGroupExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := networkfirewall.NewFromConfig(c.cfg)
	ro := func(o *networkfirewall.Options) { o.Region = region }

	// Enumerate all rule groups in the region (account-scoped, not
	// firewall-scoped).  Paginate manually to avoid a paginator import.
	var arns []string
	var nextToken *string
	for {
		listOut, err := svc.ListRuleGroups(ctx, &networkfirewall.ListRuleGroupsInput{
			NextToken: nextToken,
		}, ro)
		if err != nil {
			return nil, fmt.Errorf("ListRuleGroups: %w", err)
		}
		for _, rg := range listOut.RuleGroups {
			if rg.Arn != nil {
				arns = append(arns, aws.ToString(rg.Arn))
			}
		}
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	// Describe each rule group and collect the results.
	var results []any
	for _, arn := range arns {
		descOut, err := svc.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
			RuleGroupArn: aws.String(arn),
		}, ro)
		if err != nil {
			// Per-item error is non-fatal — the prober handles it.
			continue
		}
		results = append(results, jsonify(descOut))
	}

	return map[string]any{"RuleGroups": results}, nil
}
