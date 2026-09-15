package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

func init() {
	register("autoscaling:DescribeAutoScalingGroups", opAutoScalingDescribeAutoScalingGroups)
}

// opAutoScalingDescribeAutoScalingGroups enumerates EC2 Auto Scaling Groups (read-only).
func opAutoScalingDescribeAutoScalingGroups(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := autoscaling.NewFromConfig(c.cfg)
	p := autoscaling.NewDescribeAutoScalingGroupsPaginator(svc, &autoscaling.DescribeAutoScalingGroupsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *autoscaling.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, g := range out.AutoScalingGroups {
			recs = append(recs, Record{
				"auto_scaling_group_name": aws.ToString(g.AutoScalingGroupName),
				"arn":                     aws.ToString(g.AutoScalingGroupARN),
			})
		}
	}
	return recs, nil
}
