package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() { register("ec2:DescribeTransitGateways", opTGWDescribeTransitGateways) }

// opTGWDescribeTransitGateways enumerates Transit Gateways (read-only).
func opTGWDescribeTransitGateways(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ec2.NewFromConfig(c.cfg)
	p := ec2.NewDescribeTransitGatewaysPaginator(svc, &ec2.DescribeTransitGatewaysInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ec2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, tgw := range out.TransitGateways {
			recs = append(recs, Record{
				"transit_gateway_id":  aws.ToString(tgw.TransitGatewayId),
				"transit_gateway_arn": aws.ToString(tgw.TransitGatewayArn),
			})
		}
	}
	return recs, nil
}
