package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

func init() { register("cloudformation:DescribeStacks", opCloudFormationDescribeStacks) }

// opCloudFormationDescribeStacks enumerates CloudFormation stacks (read-only).
func opCloudFormationDescribeStacks(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := cloudformation.NewFromConfig(c.cfg)
	p := cloudformation.NewDescribeStacksPaginator(svc, &cloudformation.DescribeStacksInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *cloudformation.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, s := range out.Stacks {
			recs = append(recs, Record{
				"stack_name": aws.ToString(s.StackName),
				"stack_id":   aws.ToString(s.StackId),
			})
		}
	}
	return recs, nil
}
