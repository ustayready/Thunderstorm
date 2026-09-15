package aws

// Exposure probes for ELB/ALB/NLB — additional read_api operations beyond
// the initial DescribeTags fetcher in probe_elb.go.
//
// Inventory resource type: aws:elb:load_balancer  (native_id = load_balancer_name,
// arn = load_balancer_arn).

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

func init() {
	registerFetcher("DescribeRules", "aws:elb:load_balancer", fetchELBDescribeRulesExt)
}

// fetchELBDescribeRulesExt implements exposure probes:
//   - aws-elb-fixed-response-message-body  (DescribeRules -> Rules[].Actions[].FixedResponseConfig.MessageBody)
//   - aws-elb-redirect-url-components      (DescribeRules -> Rules[].Actions[].RedirectConfig.{Host,Path,Query})
//
// DescribeRules requires a ListenerArn, which is a sub-resource of the load
// balancer. We enumerate all listeners for the LB first via DescribeListeners,
// then fetch rules for each listener and aggregate them into a single Rules
// slice so the catalog response_path can walk all rules in one pass.
func fetchELBDescribeRulesExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := elasticloadbalancingv2.NewFromConfig(c.cfg)
	ro := func(o *elasticloadbalancingv2.Options) { o.Region = region }

	lbARN := itemStr(item, "arn", "native_id")

	// Step 1: enumerate all listeners for this load balancer.
	var listenerARNs []string
	listenerPaginator := elasticloadbalancingv2.NewDescribeListenersPaginator(svc, &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(lbARN),
	}, func(o *elasticloadbalancingv2.DescribeListenersPaginatorOptions) {})
	for listenerPaginator.HasMorePages() {
		page, err := listenerPaginator.NextPage(ctx, ro)
		if err != nil {
			return nil, fmt.Errorf("DescribeListeners(%s): %w", lbARN, err)
		}
		for _, l := range page.Listeners {
			if l.ListenerArn != nil {
				listenerARNs = append(listenerARNs, *l.ListenerArn)
			}
		}
	}

	// Step 2: fetch rules for each listener and merge into a single Rules slice.
	var allRules []any
	for _, listenerARN := range listenerARNs {
		rulesPaginator := elasticloadbalancingv2.NewDescribeRulesPaginator(svc, &elasticloadbalancingv2.DescribeRulesInput{
			ListenerArn: aws.String(listenerARN),
		}, func(o *elasticloadbalancingv2.DescribeRulesPaginatorOptions) {})
		for rulesPaginator.HasMorePages() {
			page, err := rulesPaginator.NextPage(ctx, ro)
			if err != nil {
				// Per-listener error is non-fatal — skip missing/deleted listeners.
				break
			}
			if raw := jsonify(page); raw != nil {
				if m, ok := raw.(map[string]any); ok {
					if rules, ok := m["Rules"]; ok {
						if ruleSlice, ok := rules.([]any); ok {
							allRules = append(allRules, ruleSlice...)
						}
					}
				}
			}
		}
	}

	return map[string]any{"Rules": allRules}, nil
}
