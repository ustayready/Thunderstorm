package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appflow"
)

func init() { register("appflow:ListFlows", opAppFlowListFlows) }

// opAppFlowListFlows enumerates AppFlow flows (read-only).
func opAppFlowListFlows(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := appflow.NewFromConfig(c.cfg)
	p := appflow.NewListFlowsPaginator(svc, &appflow.ListFlowsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *appflow.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Flows {
			recs = append(recs, Record{
				"flow_name": aws.ToString(item.FlowName),
				"flow_arn":  aws.ToString(item.FlowArn),
			})
		}
	}
	return recs, nil
}
