package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opsworks"
)

func init() { register("opsworks:DescribeStacks", opOpsWorksDescribeStacks) }

// opOpsWorksDescribeStacks enumerates OpsWorks stacks (read-only).
func opOpsWorksDescribeStacks(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := opsworks.NewFromConfig(c.cfg)
	out, err := svc.DescribeStacks(ctx, &opsworks.DescribeStacksInput{}, func(o *opsworks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, item := range out.Stacks {
		recs = append(recs, Record{
			"stack_id": aws.ToString(item.StackId),
			"arn":      aws.ToString(item.Arn),
		})
	}
	return recs, nil
}
