package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() { registerFactCollector("vpc-resource-policy", "regional", collectVpcPolicies) }

// collectVpcPolicies emits VPC endpoint resource-based policies as
// resource_policy facts (CrossAccountTrust surface). Each VPC endpoint in the
// region is examined; endpoints with no policy document (nil or empty) are
// silently skipped. The policy document is returned inline by
// DescribeVpcEndpoints and is URL-encoded, so urlDecode is applied before
// emission.
func collectVpcPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := ec2.NewFromConfig(c.cfg)
	ro := func(o *ec2.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := ec2.NewDescribeVpcEndpointsPaginator(svc, &ec2.DescribeVpcEndpointsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, ep := range out.VpcEndpoints {
			if ep.PolicyDocument == nil || aws.ToString(ep.PolicyDocument) == "" {
				continue // no policy attached to this endpoint
			}
			endpointID := aws.ToString(ep.VpcEndpointId)
			ownerID := aws.ToString(ep.OwnerId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc-endpoint/%s", region, ownerID, endpointID)
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				arn, "", map[string]any{"policy": urlDecode(aws.ToString(ep.PolicyDocument))})
		}
	}
	return s.n - start, nil
}
