package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
)

func init() {
	registerListFetcher("GetEnabledControl", listFetchControltowerGetEnabledControl)
}

// listFetchControltowerGetEnabledControl enumerates all enabled controls in a
// region via ListEnabledControls and fetches full details for each via
// GetEnabledControl (read-only); per-item errors are skipped.
func listFetchControltowerGetEnabledControl(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := controltower.NewFromConfig(c.cfg)
	ro := func(o *controltower.Options) { o.Region = region }
	var out []any
	p := controltower.NewListEnabledControlsPaginator(svc, &controltower.ListEnabledControlsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, it := range page.EnabledControls {
			if it.Arn == nil {
				continue
			}
			d, e := svc.GetEnabledControl(ctx, &controltower.GetEnabledControlInput{
				EnabledControlIdentifier: aws.String(*it.Arn),
			}, ro)
			if e != nil {
				continue // per-item error (access denied / not found) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}
