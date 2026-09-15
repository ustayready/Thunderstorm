package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

func init() { register("elasticloadbalancing:DescribeLoadBalancers", opELBDescribeLoadBalancers) }

// opELBDescribeLoadBalancers enumerates ALB/NLB load balancers (read-only).
func opELBDescribeLoadBalancers(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := elasticloadbalancingv2.NewFromConfig(c.cfg)
	p := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(svc, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *elasticloadbalancingv2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, lb := range out.LoadBalancers {
			recs = append(recs, Record{
				"load_balancer_name": aws.ToString(lb.LoadBalancerName),
				"load_balancer_arn":  aws.ToString(lb.LoadBalancerArn),
			})
		}
	}
	return recs, nil
}
