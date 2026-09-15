package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/detective"
)

func init() {
	registerListFetcher("ListIndicators", listFetchDetectiveListIndicators)
}

// listFetchDetectiveListIndicators enumerates all behavior graphs in the region,
// then all investigations per graph, and for each (graph, investigation) pair
// pages through ListIndicators, returning each page's response (read-only).
// The prober applies the site's response_path (Indicators[].IndicatorDetail) to
// each returned item; per-item errors are skipped.
func listFetchDetectiveListIndicators(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := detective.NewFromConfig(c.cfg)
	ro := func(o *detective.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate behavior graphs.
	gp := detective.NewListGraphsPaginator(svc, &detective.ListGraphsInput{})
	for gp.HasMorePages() {
		gPage, err := gp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, g := range gPage.GraphList {
			if g.Arn == nil {
				continue
			}
			graphArn := g.Arn

			// Step 2: enumerate investigations for this graph (manual pagination —
			// ListInvestigations has no generated paginator).
			var invNextToken *string
			for {
				invOut, err := svc.ListInvestigations(ctx, &detective.ListInvestigationsInput{
					GraphArn:  graphArn,
					NextToken: invNextToken,
				}, ro)
				if err != nil {
					break // move to next graph on error
				}
				for _, inv := range invOut.InvestigationDetails {
					if inv.InvestigationId == nil {
						continue
					}
					investigationId := inv.InvestigationId

					// Step 3: page through ListIndicators for this (graph, investigation).
					var indNextToken *string
					for {
						indOut, e := svc.ListIndicators(ctx, &detective.ListIndicatorsInput{
							GraphArn:        graphArn,
							InvestigationId: investigationId,
							NextToken:       indNextToken,
						}, ro)
						if e != nil {
							break // per-item error — skip
						}
						out = append(out, jsonify(indOut))
						if indOut.NextToken == nil || *indOut.NextToken == "" {
							break
						}
						indNextToken = indOut.NextToken
					}
				}
				if invOut.NextToken == nil || *invOut.NextToken == "" {
					break
				}
				invNextToken = invOut.NextToken
			}
		}
	}
	return out, nil
}
