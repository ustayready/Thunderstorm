package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/directconnect"
)

func init() {
	registerFetcher("DescribeVirtualInterfaces", "aws:directconnect:connection", fetchDirectconnectDescribeVirtualInterfacesExt)
}

// Exposure probe: aws-directconnect-virtual-interface-bgp-auth-key
// (DescribeVirtualInterfaces -> virtualInterfaces[].authKey).
// The inventory item is a connection; we filter by ConnectionId to retrieve all
// virtual interfaces (and their BGP auth keys) associated with that connection.
func fetchDirectconnectDescribeVirtualInterfacesExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := directconnect.NewFromConfig(c.cfg)
	connID := itemStr(item, "native_id", "arn")

	var allVifs []any
	var nextToken *string
	for {
		out, err := svc.DescribeVirtualInterfaces(ctx, &directconnect.DescribeVirtualInterfacesInput{
			ConnectionId: &connID,
			NextToken:    nextToken,
		}, func(o *directconnect.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, vif := range out.VirtualInterfaces {
			allVifs = append(allVifs, jsonify(vif))
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return map[string]any{"virtualInterfaces": allVifs}, nil
}
