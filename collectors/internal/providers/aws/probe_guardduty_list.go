package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func init() { registerListFetcher("GetFindings", listFetchGuarddutyGetFindings) }

// listFetchGuarddutyGetFindings enumerates all GuardDuty detectors in the region,
// then all finding IDs per detector, and fetches full finding details in batches
// via GetFindings (read-only); the prober applies the site's Findings[] response_path
// to each batch result. Per-detector and per-batch errors are skipped.
func listFetchGuarddutyGetFindings(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := guardduty.NewFromConfig(c.cfg)
	ro := func(o *guardduty.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate detectors in this region.
	dp := guardduty.NewListDetectorsPaginator(svc, &guardduty.ListDetectorsInput{})
	for dp.HasMorePages() {
		dPage, err := dp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, detectorID := range dPage.DetectorIds {
			detectorID := detectorID // capture loop var

			// Step 2: enumerate finding IDs for this detector.
			var ids []string
			fp := guardduty.NewListFindingsPaginator(svc, &guardduty.ListFindingsInput{
				DetectorId: &detectorID,
			})
			for fp.HasMorePages() {
				fPage, err := fp.NextPage(ctx, ro)
				if err != nil {
					break // move to next detector on error
				}
				ids = append(ids, fPage.FindingIds...)
			}

			// Step 3: fetch findings in batches of 50 (API maximum).
			const batchSize = 50
			for i := 0; i < len(ids); i += batchSize {
				end := i + batchSize
				if end > len(ids) {
					end = len(ids)
				}
				batch := ids[i:end]
				d, e := svc.GetFindings(ctx, &guardduty.GetFindingsInput{
					DetectorId: &detectorID,
					FindingIds: batch,
				}, ro)
				if e != nil {
					continue // per-batch error — skip
				}
				out = append(out, jsonify(d))
			}
		}
	}
	return out, nil
}
