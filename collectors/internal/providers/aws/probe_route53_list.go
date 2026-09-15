package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/route53"
)

func init() { registerListFetcher("GetHealthCheck", listFetchRoute53GetHealthCheck) }

// listFetchRoute53GetHealthCheck enumerates every Route 53 health check in the
// account (health checks are global, not per-region), calls GetHealthCheck for
// each, and returns the detail responses so the prober can apply the site's
// response_path (HealthCheck.HealthCheckConfig.SearchString) to each.
// Per-item errors (not-found, access-denied) are skipped rather than failing
// the whole fetch.
func listFetchRoute53GetHealthCheck(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := route53.NewFromConfig(c.cfg)
	ro := func(o *route53.Options) { o.Region = region }

	var out []any
	p := route53.NewListHealthChecksPaginator(svc, &route53.ListHealthChecksInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, hc := range page.HealthChecks {
			if hc.Id == nil {
				continue
			}
			d, e := svc.GetHealthCheck(ctx, &route53.GetHealthCheckInput{
				HealthCheckId: hc.Id,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access denied) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}
