package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/macie2"
)

func init() {
	registerListFetcher("GetFindings", listFetchMacieGetFindings)
	registerListFetcher("GetCustomDataIdentifier", listFetchMacieGetCustomDataIdentifier)
}

// listFetchMacieGetFindings enumerates all finding IDs in the region via
// ListFindings, then fetches full detail for each via GetFindings (up to 50
// IDs per call as permitted by the API); per-item errors are skipped.
func listFetchMacieGetFindings(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := macie2.NewFromConfig(c.cfg)
	ro := func(o *macie2.Options) { o.Region = region }
	var out []any

	// Collect all finding IDs via paginated ListFindings.
	var findingIDs []string
	p := macie2.NewListFindingsPaginator(svc, &macie2.ListFindingsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		findingIDs = append(findingIDs, page.FindingIds...)
	}

	// GetFindings accepts up to 50 IDs per call.
	const batchSize = 50
	for i := 0; i < len(findingIDs); i += batchSize {
		end := i + batchSize
		if end > len(findingIDs) {
			end = len(findingIDs)
		}
		batch := findingIDs[i:end]
		d, e := svc.GetFindings(ctx, &macie2.GetFindingsInput{
			FindingIds: batch,
		}, ro)
		if e != nil {
			continue // per-batch error — skip
		}
		out = append(out, jsonify(d))
	}
	return out, nil
}

// listFetchMacieGetCustomDataIdentifier enumerates all custom data identifiers
// in the region via ListCustomDataIdentifiers, then fetches full detail for
// each via GetCustomDataIdentifier (read-only); per-item errors are skipped.
func listFetchMacieGetCustomDataIdentifier(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := macie2.NewFromConfig(c.cfg)
	ro := func(o *macie2.Options) { o.Region = region }
	var out []any

	p := macie2.NewListCustomDataIdentifiersPaginator(svc, &macie2.ListCustomDataIdentifiersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, item := range page.Items {
			if item.Id == nil {
				continue
			}
			d, e := svc.GetCustomDataIdentifier(ctx, &macie2.GetCustomDataIdentifierInput{
				Id: item.Id,
			}, ro)
			if e != nil {
				continue // per-item error — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}
