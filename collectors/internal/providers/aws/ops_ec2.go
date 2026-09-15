package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() { register("ec2:DescribeInstances", opEC2DescribeInstances) }

// opEC2DescribeInstances enumerates EC2 instances (read-only).
func opEC2DescribeInstances(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ec2.NewFromConfig(c.cfg)
	p := ec2.NewDescribeInstancesPaginator(svc, &ec2.DescribeInstancesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ec2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, r := range out.Reservations {
			for _, inst := range r.Instances {
				recs = append(recs, Record{
					"instance_id": aws.ToString(inst.InstanceId),
				})
			}
		}
	}
	return recs, nil
}
