package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

func init() { register("states:ListStateMachines", opSFNListStateMachines) }

// opSFNListStateMachines enumerates Step Functions state machines (read-only).
func opSFNListStateMachines(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := sfn.NewFromConfig(c.cfg)
	p := sfn.NewListStateMachinesPaginator(svc, &sfn.ListStateMachinesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *sfn.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, sm := range out.StateMachines {
			recs = append(recs, Record{
				"name": aws.ToString(sm.Name),
				"arn":  aws.ToString(sm.StateMachineArn),
			})
		}
	}
	return recs, nil
}
