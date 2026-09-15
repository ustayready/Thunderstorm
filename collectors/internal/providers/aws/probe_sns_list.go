package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func init() {
	registerListFetcher("GetPlatformApplicationAttributes", listFetchSnsGetPlatformApplicationAttributes)
	registerListFetcher("GetEndpointAttributes", listFetchSnsGetEndpointAttributes)
}

// listFetchSnsGetPlatformApplicationAttributes enumerates all SNS platform
// applications in a region and returns GetPlatformApplicationAttributes for
// each (read-only); per-item errors are skipped.
func listFetchSnsGetPlatformApplicationAttributes(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := sns.NewFromConfig(c.cfg)
	ro := func(o *sns.Options) { o.Region = region }
	var out []any
	p := sns.NewListPlatformApplicationsPaginator(svc, &sns.ListPlatformApplicationsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, app := range page.PlatformApplications {
			if app.PlatformApplicationArn == nil {
				continue
			}
			d, e := svc.GetPlatformApplicationAttributes(ctx, &sns.GetPlatformApplicationAttributesInput{
				PlatformApplicationArn: app.PlatformApplicationArn,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access denied) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchSnsGetEndpointAttributes enumerates all SNS platform applications in
// a region, then all endpoints per application, and returns
// GetEndpointAttributes for each endpoint (read-only); per-item errors are
// skipped.
func listFetchSnsGetEndpointAttributes(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := sns.NewFromConfig(c.cfg)
	ro := func(o *sns.Options) { o.Region = region }
	var out []any
	appPager := sns.NewListPlatformApplicationsPaginator(svc, &sns.ListPlatformApplicationsInput{})
	for appPager.HasMorePages() {
		appPage, err := appPager.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, app := range appPage.PlatformApplications {
			if app.PlatformApplicationArn == nil {
				continue
			}
			epPager := sns.NewListEndpointsByPlatformApplicationPaginator(svc, &sns.ListEndpointsByPlatformApplicationInput{
				PlatformApplicationArn: app.PlatformApplicationArn,
			})
			for epPager.HasMorePages() {
				epPage, err := epPager.NextPage(ctx, ro)
				if err != nil {
					break // skip remaining pages for this app on error
				}
				for _, ep := range epPage.Endpoints {
					if ep.EndpointArn == nil {
						continue
					}
					d, e := svc.GetEndpointAttributes(ctx, &sns.GetEndpointAttributesInput{
						EndpointArn: ep.EndpointArn,
					}, ro)
					if e != nil {
						continue // per-item error — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}
