package aws

import (
	"context"
	"encoding/json"

	"thunderstorm/collector/internal/exposure"
)

// FetchFunc fetches the raw response for one exposure operation over one
// inventory item (read-only). Return jsonify(sdkOutput) so the prober can apply
// the catalog's response_path generically.
type FetchFunc func(ctx context.Context, c *Client, region string, item map[string]any) (any, error)

type fetcherReg struct {
	resourceType string
	fn           FetchFunc
}

// exposureFetchers is populated by per-service probe_*.go files via init() →
// registerFetcher, so probe breadth is added without editing this file.
var exposureFetchers = map[string]fetcherReg{}

func registerFetcher(operation, resourceType string, fn FetchFunc) {
	exposureFetchers[operation] = fetcherReg{resourceType, fn}
}

// ExposureFetchers builds the prober's FetcherSet bound to this client.
func ExposureFetchers(c *Client) exposure.FetcherSet {
	set := exposure.FetcherSet{}
	for op, r := range exposureFetchers {
		r := r
		set[op] = exposure.Fetcher{
			ResourceType: r.resourceType,
			Fetch: func(ctx context.Context, region string, item map[string]any) (any, error) {
				return r.fn(ctx, c, region, item)
			},
		}
	}
	return set
}

// ListFetchFunc is a SELF-ENUMERATING exposure fetcher: it lists its own target
// sub-resources for a region and returns 0..N jsonified responses (the prober
// applies the site's response_path to each). For ops whose targets aren't in
// inventory (findings, dashboards, health checks, ...).
type ListFetchFunc func(ctx context.Context, c *Client, region string) ([]any, error)

var exposureListFetchers = map[string]ListFetchFunc{}

func registerListFetcher(operation string, fn ListFetchFunc) {
	exposureListFetchers[operation] = fn
}

// ExposureListFetchers builds the prober's self-enumerating fetcher set.
func ExposureListFetchers(c *Client) exposure.ListFetcherSet {
	set := exposure.ListFetcherSet{}
	for op, fn := range exposureListFetchers {
		fn := fn
		set[op] = exposure.ListFetcher{
			Fetch: func(ctx context.Context, region string) ([]any, error) { return fn(ctx, c, region) },
		}
	}
	return set
}

// jsonify converts an SDK output struct to generic map[string]any / []any so the
// prober's nested response-path extractor can walk it.
func jsonify(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// itemStr returns the first non-empty string among the named item keys — the
// helper fetchers use to pull an id/arn/name from an inventory item.
func itemStr(item map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := item[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
