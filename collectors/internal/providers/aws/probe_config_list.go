package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

func init() {
	registerListFetcher("BatchGetResourceConfig", listFetchConfigBatchGetResourceConfig)
}

// listFetchConfigBatchGetResourceConfig enumerates all resource types being
// recorded by AWS Config in the region, pages through their resource IDs via
// ListDiscoveredResources, then fetches full configuration snapshots in batches
// of 100 using BatchGetResourceConfig (read-only). Each BaseConfigurationItem is
// returned as a jsonified value so the prober can apply the site's
// response_path (baseConfigurationItems[].{configuration,supplementaryConfiguration}).
func listFetchConfigBatchGetResourceConfig(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := configservice.NewFromConfig(c.cfg)
	ro := func(o *configservice.Options) { o.Region = region }

	// Step 1: collect all resource types currently tracked in this region.
	var resourceTypes []cstypes.ResourceType
	countPager := configservice.NewGetDiscoveredResourceCountsPaginator(svc, &configservice.GetDiscoveredResourceCountsInput{})
	for countPager.HasMorePages() {
		page, err := countPager.NextPage(ctx, ro)
		if err != nil {
			return nil, err
		}
		for _, rc := range page.ResourceCounts {
			if rc.ResourceType != "" {
				resourceTypes = append(resourceTypes, rc.ResourceType)
			}
		}
	}

	// Step 2: for each resource type, page through discovered resource IDs.
	var keys []cstypes.ResourceKey
	for _, rt := range resourceTypes {
		resPager := configservice.NewListDiscoveredResourcesPaginator(svc, &configservice.ListDiscoveredResourcesInput{
			ResourceType: rt,
		})
		for resPager.HasMorePages() {
			page, err := resPager.NextPage(ctx, ro)
			if err != nil {
				break // per-type error — skip to next type
			}
			for _, ri := range page.ResourceIdentifiers {
				if ri.ResourceId != nil {
					keys = append(keys, cstypes.ResourceKey{
						ResourceType: ri.ResourceType,
						ResourceId:   ri.ResourceId,
					})
				}
			}
		}
	}

	// Step 3: batch-fetch configuration (BatchGetResourceConfig accepts up to 100 keys).
	const batchSize = 100
	var out []any
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		batch := keys[i:end]
		resp, err := svc.BatchGetResourceConfig(ctx, &configservice.BatchGetResourceConfigInput{
			ResourceKeys: batch,
		}, ro)
		if err != nil {
			continue // per-batch error (access denied, etc.) — skip
		}
		for _, item := range resp.BaseConfigurationItems {
			item := item
			out = append(out, jsonify(item))
		}
	}
	return out, nil
}
