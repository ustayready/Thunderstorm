package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

func init() { register("eventbridge:ListEventBuses", opEventBridgeListEventBuses) }

// opEventBridgeListEventBuses enumerates EventBridge event buses (read-only).
func opEventBridgeListEventBuses(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := eventbridge.NewFromConfig(c.cfg)
	out, err := svc.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{}, func(o *eventbridge.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, bus := range out.EventBuses {
		recs = append(recs, Record{
			"name": aws.ToString(bus.Name),
			"arn":  aws.ToString(bus.Arn),
		})
	}
	return recs, nil
}
