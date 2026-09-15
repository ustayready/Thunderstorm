package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() { register("vpc:DescribeVpcs", opVPCDescribeVpcs) }

// opVPCDescribeVpcs enumerates VPCs (read-only).
func opVPCDescribeVpcs(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ec2.NewFromConfig(c.cfg)
	p := ec2.NewDescribeVpcsPaginator(svc, &ec2.DescribeVpcsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ec2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, v := range out.Vpcs {
			id := aws.ToString(v.VpcId)
			acct := aws.ToString(v.OwnerId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, acct, id)
			recs = append(recs, Record{
				"vpc_id": id,
				"arn":    arn,
			})
		}
	}
	return recs, nil
}
