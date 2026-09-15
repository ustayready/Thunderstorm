package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

func init() {
	registerListFetcher("GetFindings", listFetchSecurityhubGetFindings)
	registerListFetcher("BatchGetAutomationRules", listFetchSecurityhubBatchGetAutomationRules)
}

// listFetchSecurityhubGetFindings paginates GetFindings across the region and
// returns each finding as a separate jsonified entry (read-only); the prober
// applies the site's response_path to each element.
func listFetchSecurityhubGetFindings(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := securityhub.NewFromConfig(c.cfg)
	ro := func(o *securityhub.Options) { o.Region = region }
	var out []any

	p := securityhub.NewGetFindingsPaginator(svc, &securityhub.GetFindingsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, f := range page.Findings {
			out = append(out, jsonify(f))
		}
	}
	return out, nil
}

// listFetchSecurityhubBatchGetAutomationRules enumerates automation rules via
// ListAutomationRules, then fetches full rule details via BatchGetAutomationRules
// (read-only); per-batch errors are skipped.
func listFetchSecurityhubBatchGetAutomationRules(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := securityhub.NewFromConfig(c.cfg)
	ro := func(o *securityhub.Options) { o.Region = region }
	var out []any

	// Collect all rule ARNs from ListAutomationRules (no SDK paginator — manual token loop).
	var arns []string
	var nextToken *string
	for {
		page, err := svc.ListAutomationRules(ctx, &securityhub.ListAutomationRulesInput{
			NextToken: nextToken,
		}, ro)
		if err != nil {
			return out, err
		}
		for _, m := range page.AutomationRulesMetadata {
			if m.RuleArn != nil {
				arns = append(arns, *m.RuleArn)
			}
		}
		if page.NextToken == nil {
			break
		}
		nextToken = page.NextToken
	}

	// BatchGetAutomationRules accepts up to 100 ARNs per call.
	const batchSize = 100
	for i := 0; i < len(arns); i += batchSize {
		end := i + batchSize
		if end > len(arns) {
			end = len(arns)
		}
		d, e := svc.BatchGetAutomationRules(ctx, &securityhub.BatchGetAutomationRulesInput{
			AutomationRulesArns: arns[i:end],
		}, ro)
		if e != nil {
			continue // per-batch error — skip
		}
		out = append(out, jsonify(d))
	}
	return out, nil
}
