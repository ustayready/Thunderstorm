package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func init() {
	registerListFetcher("GetRegexPatternSet", listFetchWafGetRegexPatternSet)
}

// listFetchWafGetRegexPatternSet enumerates all WAFv2 RegexPatternSets in the
// region (REGIONAL scope) and returns each GetRegexPatternSet response as a
// jsonified value. The prober applies the site's response_path
// (RegexPatternSet.RegularExpressionList[].RegexString) to each result.
//
// ListRegexPatternSets has no SDK paginator; pagination is done manually via
// NextMarker.
func listFetchWafGetRegexPatternSet(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := wafv2.NewFromConfig(c.cfg)
	ro := func(o *wafv2.Options) { o.Region = region }

	var (
		out        []any
		nextMarker *string
	)
	for {
		page, err := svc.ListRegexPatternSets(ctx, &wafv2.ListRegexPatternSetsInput{
			Scope:      types.ScopeRegional,
			Limit:      aws.Int32(100),
			NextMarker: nextMarker,
		}, ro)
		if err != nil {
			return out, err
		}
		for _, summary := range page.RegexPatternSets {
			if summary.Id == nil || summary.Name == nil {
				continue
			}
			d, e := svc.GetRegexPatternSet(ctx, &wafv2.GetRegexPatternSetInput{
				Id:    summary.Id,
				Name:  summary.Name,
				Scope: types.ScopeRegional,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access denied) — skip
			}
			out = append(out, jsonify(d))
		}
		if page.NextMarker == nil || *page.NextMarker == "" {
			break
		}
		nextMarker = page.NextMarker
	}
	return out, nil
}
