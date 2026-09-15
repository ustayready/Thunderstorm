package aws

// Exposure probe: aws-eks-addon-configuration-values (DescribeAddon -> addon.configurationValues).
//
// The inventory item is an EKS cluster (aws:eks:cluster); native_id is the
// cluster name. Because DescribeAddon requires both clusterName and addonName,
// this fetcher first enumerates all installed add-ons via ListAddons and then
// calls DescribeAddon for each one, aggregating results under a top-level
// "addons" list so the catalog response_path "addon.configurationValues" can
// be applied per-element by the prober.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func init() {
	registerFetcher("DescribeAddon", "aws:eks:cluster", fetchEksDescribeAddonExt)
}

// fetchEksDescribeAddonExt enumerates all add-ons for the cluster identified by
// native_id and calls DescribeAddon for each, returning a map with an "addons"
// slice so the prober can walk addon.configurationValues across every add-on.
func fetchEksDescribeAddonExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := eks.NewFromConfig(c.cfg)
	ro := func(o *eks.Options) { o.Region = region }

	clusterName := itemStr(item, "native_id", "arn")

	// Paginate through all installed add-on names for this cluster.
	var addonNames []string
	var nextToken *string
	for {
		listOut, err := svc.ListAddons(ctx, &eks.ListAddonsInput{
			ClusterName: aws.String(clusterName),
			NextToken:   nextToken,
		}, ro)
		if err != nil {
			return nil, fmt.Errorf("ListAddons(%s): %w", clusterName, err)
		}
		addonNames = append(addonNames, listOut.Addons...)
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	// Describe each add-on and collect the results.
	var addons []any
	for _, name := range addonNames {
		descOut, err := svc.DescribeAddon(ctx, &eks.DescribeAddonInput{
			ClusterName: aws.String(clusterName),
			AddonName:   aws.String(name),
		}, ro)
		if err != nil {
			// Per-addon errors are non-fatal; skip deleted or inaccessible addons.
			continue
		}
		addons = append(addons, jsonify(descOut))
	}

	return map[string]any{"addons": addons}, nil
}
