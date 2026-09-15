package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func init() { register("ssm:DescribeParameters", opSSMParamsDescribeParameters) }

// opSSMParamsDescribeParameters enumerates SSM Parameter Store parameters (read-only).
func opSSMParamsDescribeParameters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ssm.NewFromConfig(c.cfg)
	p := ssm.NewDescribeParametersPaginator(svc, &ssm.DescribeParametersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ssm.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Parameters {
			recs = append(recs, Record{
				"parameter_name": aws.ToString(item.Name),
				"arn":            aws.ToString(item.ARN),
			})
		}
	}
	return recs, nil
}
