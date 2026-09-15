package aws

// Exposure probes for EventBridge — additional read_api operations beyond
// ListTagsForResource (already in probe_eventbridge.go).
//
// The only inventory resource type is aws:eventbridge:event_bus whose
// native_id is the event bus name.  Rules are sub-resources enumerated via
// ListRules(EventBusName=<bus-name>); we fan out from there.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

func init() {
	registerFetcher("ListTargetsByRule", "aws:eventbridge:event_bus", fetchEventBridgeListTargetsByRuleExt)
	registerFetcher("DescribeRule", "aws:eventbridge:event_bus", fetchEventBridgeDescribeRuleExt)
}

// fetchEventBridgeListTargetsByRuleExt implements the exposure probe
// aws-eventbridge-rule-target-static-input (ListTargetsByRule ->
// Targets[].Input / InputTransformer.InputTemplate / HttpParameters).
//
// The inventory item is an event bus, not an individual rule, so we first
// enumerate all rules for the bus via ListRules, then call ListTargetsByRule
// for each.  All target lists are merged into a single top-level "Targets"
// slice so the catalog response_path resolves against the aggregated result.
func fetchEventBridgeListTargetsByRuleExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := eventbridge.NewFromConfig(c.cfg)
	ro := func(o *eventbridge.Options) { o.Region = region }

	busName := itemStr(item, "native_id", "name", "arn")

	rules, err := listEventBridgeRules(ctx, svc, ro, busName)
	if err != nil {
		return nil, fmt.Errorf("ListRules(%s): %w", busName, err)
	}

	var allTargets []any
	for _, ruleName := range rules {
		out, err := svc.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
			Rule:         aws.String(ruleName),
			EventBusName: aws.String(busName),
		}, ro)
		if err != nil {
			// Per-rule errors are non-fatal — skip deleted/inaccessible rules.
			continue
		}
		for _, t := range out.Targets {
			allTargets = append(allTargets, jsonify(t))
		}
	}

	return map[string]any{"Targets": allTargets}, nil
}

// fetchEventBridgeDescribeRuleExt implements the exposure probe
// aws-eventbridge-rule-event-pattern (DescribeRule -> EventPattern).
//
// Rules are enumerated from the bus via ListRules; DescribeRule is called for
// each.  All EventPattern strings and rule metadata are merged into a single
// "Rules" slice so the catalog response_path "EventPattern" can be applied
// across them.
func fetchEventBridgeDescribeRuleExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := eventbridge.NewFromConfig(c.cfg)
	ro := func(o *eventbridge.Options) { o.Region = region }

	busName := itemStr(item, "native_id", "name", "arn")

	rules, err := listEventBridgeRules(ctx, svc, ro, busName)
	if err != nil {
		return nil, fmt.Errorf("ListRules(%s): %w", busName, err)
	}

	var allRules []any
	for _, ruleName := range rules {
		out, err := svc.DescribeRule(ctx, &eventbridge.DescribeRuleInput{
			Name:         aws.String(ruleName),
			EventBusName: aws.String(busName),
		}, ro)
		if err != nil {
			// Per-rule errors are non-fatal.
			continue
		}
		allRules = append(allRules, jsonify(out))
	}

	return map[string]any{"Rules": allRules}, nil
}

// listEventBridgeRules pages through ListRules for the given event bus and
// returns all rule names.
func listEventBridgeRules(ctx context.Context, svc *eventbridge.Client, ro func(*eventbridge.Options), busName string) ([]string, error) {
	var names []string
	var nextToken *string
	for {
		out, err := svc.ListRules(ctx, &eventbridge.ListRulesInput{
			EventBusName: aws.String(busName),
			NextToken:    nextToken,
		}, ro)
		if err != nil {
			return nil, err
		}
		for _, r := range out.Rules {
			names = append(names, aws.ToString(r.Name))
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return names, nil
}
