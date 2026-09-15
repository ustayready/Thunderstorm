package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// collectNetworkFacts emits the reachability facts the network-chains linchpin
// composes: security-group ingress rules (CanReachPort), VPC peering
// (PeeredWith), and route-table entries (RoutesTo).
func collectNetworkFacts(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := ec2.NewFromConfig(c.cfg)
	ro := func(o *ec2.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	// Security-group ingress → CanReachPort (source = cidr or source SG, target = SG).
	sgp := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{})
	for sgp.HasMorePages() {
		out, err := sgp.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, sg := range out.SecurityGroups {
			sgid := aws.ToString(sg.GroupId)
			for _, perm := range sg.IpPermissions {
				attrs := map[string]any{
					"protocol":  aws.ToString(perm.IpProtocol),
					"from_port": int32ptr(perm.FromPort),
					"to_port":   int32ptr(perm.ToPort),
				}
				for _, r := range perm.IpRanges {
					s.emitFact("network_rule", "CanReachPort", scope, aws.ToString(r.CidrIp), sgid, attrs)
				}
				for _, r := range perm.Ipv6Ranges {
					s.emitFact("network_rule", "CanReachPort", scope, aws.ToString(r.CidrIpv6), sgid, attrs)
				}
				for _, g := range perm.UserIdGroupPairs {
					s.emitFact("network_rule", "CanReachPort", scope, aws.ToString(g.GroupId), sgid, attrs)
				}
			}
		}
	}

	// VPC peering → PeeredWith.
	if pc, err := svc.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{}, ro); err == nil {
		for _, p := range pc.VpcPeeringConnections {
			var req, acc string
			if p.RequesterVpcInfo != nil {
				req = aws.ToString(p.RequesterVpcInfo.VpcId)
			}
			if p.AccepterVpcInfo != nil {
				acc = aws.ToString(p.AccepterVpcInfo.VpcId)
			}
			s.emitFact("peering", "PeeredWith", scope, req, acc, nil)
		}
	}

	// Route tables → RoutesTo (source = route table, target = gateway/tgw/peering/nat).
	rtp := ec2.NewDescribeRouteTablesPaginator(svc, &ec2.DescribeRouteTablesInput{})
	for rtp.HasMorePages() {
		out, err := rtp.NextPage(ctx, ro)
		if err != nil {
			break
		}
		for _, rt := range out.RouteTables {
			rtid := aws.ToString(rt.RouteTableId)
			for _, e := range rt.Routes {
				target := firstNonEmpty(aws.ToString(e.TransitGatewayId), aws.ToString(e.VpcPeeringConnectionId),
					aws.ToString(e.NatGatewayId), aws.ToString(e.GatewayId))
				if target == "" {
					continue
				}
				dest := firstNonEmpty(aws.ToString(e.DestinationCidrBlock), aws.ToString(e.DestinationPrefixListId))
				s.emitFact("route", "RoutesTo", scope, rtid, target, map[string]any{"destination": dest})
			}
		}
	}
	return s.n - start, nil
}
