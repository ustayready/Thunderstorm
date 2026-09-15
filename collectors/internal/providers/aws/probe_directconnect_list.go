package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/directconnect"
)

func init() {
	registerListFetcher("DescribeRouterConfiguration", listFetchDirectconnectDescribeRouterConfiguration)
}

// listFetchDirectconnectDescribeRouterConfiguration enumerates all virtual
// interfaces in the region and returns the router configuration for each
// (read-only). RouterTypeIdentifier is omitted to retrieve the default
// configuration; per-item errors are skipped so one inaccessible VIF does
// not abort the whole sweep.
func listFetchDirectconnectDescribeRouterConfiguration(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := directconnect.NewFromConfig(c.cfg)
	ro := func(o *directconnect.Options) { o.Region = region }

	// Step 1: enumerate all virtual interfaces in the region.
	var vifIDs []string
	var nextToken *string
	for {
		page, err := svc.DescribeVirtualInterfaces(ctx, &directconnect.DescribeVirtualInterfacesInput{
			NextToken: nextToken,
		}, ro)
		if err != nil {
			return nil, err
		}
		for _, vif := range page.VirtualInterfaces {
			if vif.VirtualInterfaceId != nil {
				vifIDs = append(vifIDs, *vif.VirtualInterfaceId)
			}
		}
		if page.NextToken == nil {
			break
		}
		nextToken = page.NextToken
	}

	// Step 2: fetch router configuration for each virtual interface.
	var out []any
	for _, id := range vifIDs {
		id := id
		d, err := svc.DescribeRouterConfiguration(ctx, &directconnect.DescribeRouterConfigurationInput{
			VirtualInterfaceId: &id,
		}, ro)
		if err != nil {
			continue // per-item error (not found / access denied) — skip
		}
		out = append(out, jsonify(d))
	}
	return out, nil
}
