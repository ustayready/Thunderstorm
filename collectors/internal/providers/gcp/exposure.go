package gcp

import (
	"context"
	"strings"

	"thunderstorm/collector/internal/exposure"
)

// GCP exposure probing reuses the same generic REST invoker as inventory: an
// exposure operation (a get / access / getIamPolicy method) resolves to an
// endpoint spec in gcpOps and is called over an inventory item. The set of
// exposure ops and their fetcher wiring is populated in M5c (exposure_gen.go)
// via registerExposureOp; M5a ships the plumbing.

// exposureOp names an inventory-driven exposure fetch: the catalog operation, the
// resource_type whose inventory drives it, and the bound param name that carries
// the resource identifier into the endpoint spec's {param}.
type exposureOp struct {
	resourceType string
	nameParam    string // path/query param the item's native_id/arn binds to (e.g. "name")
}

var exposureOps = map[string]exposureOp{}

// registerExposureOp wires a catalog operation to a resource_type + bound param.
func registerExposureOp(operation, resourceType, nameParam string) {
	exposureOps[operation] = exposureOp{resourceType, nameParam}
}

// ExposureFetchers builds the prober's FetcherSet: each registered exposure op
// invokes the generic REST endpoint for that operation over the inventory item,
// binding the item's identifier into the endpoint's {param}.
func ExposureFetchers(c *Client) exposure.FetcherSet {
	set := exposure.FetcherSet{}
	for op, e := range exposureOps {
		op, e := op, e
		set[op] = exposure.Fetcher{
			ResourceType: e.resourceType,
			Fetch: func(ctx context.Context, region string, item map[string]any) (any, error) {
				id := itemID(item)
				// Sub-resource ops target a child of the inventory item: a secret's
				// version access needs /versions/latest (inventory yields the secret).
				if strings.HasSuffix(op, ".versions.access") && !strings.Contains(id, "/versions/") {
					id += "/versions/latest"
				}
				params := map[string]string{e.nameParam: id}
				recs, err := c.Invoke(ctx, op, region, params)
				if err != nil {
					return nil, err
				}
				if len(recs) == 1 {
					return map[string]any(recs[0]), nil
				}
				out := make([]any, 0, len(recs))
				for _, r := range recs {
					out = append(out, map[string]any(r))
				}
				return out, nil
			},
		}
	}
	return set
}

// ExposureListFetchers: GCP self-enumerating exposure fetchers (M5c). Empty today.
func ExposureListFetchers(c *Client) exposure.ListFetcherSet {
	return exposure.ListFetcherSet{}
}

// itemID pulls the GCP resource identifier from an inventory item — GCP resource
// names (projects/…/x) live under "name"/"arn"/"native_id".
func itemID(item map[string]any) string {
	for _, k := range []string{"name", "arn", "native_id"} {
		if v, ok := item[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
