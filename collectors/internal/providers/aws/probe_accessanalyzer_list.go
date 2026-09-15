package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
)

func init() {
	registerListFetcher("GetFindingV2", listFetchAccessanalyzerGetFindingV2)
	registerListFetcher("GetArchiveRule", listFetchAccessanalyzerGetArchiveRule)
}

// listFetchAccessanalyzerGetFindingV2 enumerates all analyzers in the region,
// then all findings per analyzer, and fetches full detail for each via
// GetFindingV2 (read-only); per-item errors are skipped.
func listFetchAccessanalyzerGetFindingV2(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := accessanalyzer.NewFromConfig(c.cfg)
	ro := func(o *accessanalyzer.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate analyzers.
	ap := accessanalyzer.NewListAnalyzersPaginator(svc, &accessanalyzer.ListAnalyzersInput{})
	for ap.HasMorePages() {
		aPage, err := ap.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, az := range aPage.Analyzers {
			analyzerArn := az.Arn
			if analyzerArn == nil {
				continue
			}

			// Step 2: enumerate findings for this analyzer.
			fp := accessanalyzer.NewListFindingsV2Paginator(svc, &accessanalyzer.ListFindingsV2Input{
				AnalyzerArn: analyzerArn,
			})
			for fp.HasMorePages() {
				fPage, err := fp.NextPage(ctx, ro)
				if err != nil {
					break // move to next analyzer on error
				}
				for _, f := range fPage.Findings {
					if f.Id == nil {
						continue
					}
					// Step 3: fetch full finding detail.
					d, e := svc.GetFindingV2(ctx, &accessanalyzer.GetFindingV2Input{
						AnalyzerArn: analyzerArn,
						Id:          f.Id,
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

// listFetchAccessanalyzerGetArchiveRule enumerates all analyzers in the region,
// then all archive rules per analyzer, and fetches full detail for each via
// GetArchiveRule (read-only); per-item errors are skipped.
func listFetchAccessanalyzerGetArchiveRule(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := accessanalyzer.NewFromConfig(c.cfg)
	ro := func(o *accessanalyzer.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate analyzers.
	ap := accessanalyzer.NewListAnalyzersPaginator(svc, &accessanalyzer.ListAnalyzersInput{})
	for ap.HasMorePages() {
		aPage, err := ap.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, az := range aPage.Analyzers {
			analyzerName := az.Name
			if analyzerName == nil {
				continue
			}

			// Step 2: enumerate archive rules for this analyzer.
			rp := accessanalyzer.NewListArchiveRulesPaginator(svc, &accessanalyzer.ListArchiveRulesInput{
				AnalyzerName: analyzerName,
			})
			for rp.HasMorePages() {
				rPage, err := rp.NextPage(ctx, ro)
				if err != nil {
					break // move to next analyzer on error
				}
				for _, rule := range rPage.ArchiveRules {
					if rule.RuleName == nil {
						continue
					}
					// Step 3: fetch full archive rule detail.
					d, e := svc.GetArchiveRule(ctx, &accessanalyzer.GetArchiveRuleInput{
						AnalyzerName: analyzerName,
						RuleName:     rule.RuleName,
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
