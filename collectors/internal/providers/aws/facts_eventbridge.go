package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

func init() {
	registerFactCollector("eventbridge-resource-policy", "regional", collectEventbridgePolicies)
}

// collectEventbridgePolicies emits EventBridge event bus resource-based policies
// as resource_policy facts (CrossAccountTrust surface). Both the default event
// bus and custom/partner event buses can carry a resource-based policy that
// grants cross-account PutEvents access.
//
// ListEventBuses returns the Policy field inline, so no separate DescribeEventBus
// call is required. Buses with no policy (nil or empty) are silently skipped.
func collectEventbridgePolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := eventbridge.NewFromConfig(c.cfg)
	ro := func(o *eventbridge.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	var nextToken *string
	for {
		out, err := svc.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
			NextToken: nextToken,
		}, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, bus := range out.EventBuses {
			if bus.Policy == nil || aws.ToString(bus.Policy) == "" {
				continue // no resource-based policy on this bus
			}
			src := firstNonEmpty(aws.ToString(bus.Arn), aws.ToString(bus.Name))
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				src, "", map[string]any{"policy": aws.ToString(bus.Policy)})
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return s.n - start, nil
}
