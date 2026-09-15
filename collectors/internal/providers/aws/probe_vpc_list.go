package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() {
	registerListFetcher("DescribeVpnConnections", listFetchVpcDescribeVpnConnections)
	registerListFetcher("DescribeVpcEndpoints", listFetchVpcDescribeVpcEndpoints)
}

// listFetchVpcDescribeVpnConnections enumerates all VPN connections in the
// region and returns each as a jsonified response so the prober can extract
// VpnConnections[].CustomerGatewayConfiguration via response_path.
// DescribeVpnConnections is not paginated — one call returns all connections.
// Read-only; per-region errors are surfaced to the caller.
func listFetchVpcDescribeVpnConnections(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ec2.NewFromConfig(c.cfg)
	ro := func(o *ec2.Options) { o.Region = region }

	out, err := svc.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{}, ro)
	if err != nil {
		return nil, err
	}

	var results []any
	for _, conn := range out.VpnConnections {
		conn := conn
		results = append(results, jsonify(conn))
	}
	return results, nil
}

// listFetchVpcDescribeVpcEndpoints enumerates all VPC endpoints in the region
// and returns each as a jsonified response so the prober can extract
// VpcEndpoints[].PolicyDocument via response_path.
// Read-only; per-page errors are surfaced to the caller.
func listFetchVpcDescribeVpcEndpoints(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ec2.NewFromConfig(c.cfg)
	ro := func(o *ec2.Options) { o.Region = region }

	var results []any
	p := ec2.NewDescribeVpcEndpointsPaginator(svc, &ec2.DescribeVpcEndpointsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return results, err
		}
		for _, ep := range page.VpcEndpoints {
			ep := ep
			results = append(results, jsonify(ep))
		}
	}
	return results, nil
}
