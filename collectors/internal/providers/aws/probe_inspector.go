package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

func init() {
	registerFetcher("ListFindings", "aws:inspector:finding", fetchInspectorListFindings)
	registerFetcher("ListTagsForResource", "aws:inspector:finding", fetchInspectorListTagsForResource)
}

// Exposure probe: aws-inspector-finding-resource-details (ListFindings -> findings[]).
func fetchInspectorListFindings(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	arn := itemStr(item, "native_id", "arn")
	out, err := inspector2.NewFromConfig(c.cfg).ListFindings(ctx, &inspector2.ListFindingsInput{
		FilterCriteria: &types.FilterCriteria{
			FindingArn: []types.StringFilter{
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String(arn),
				},
			},
		},
	}, func(o *inspector2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-inspector-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchInspectorListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := inspector2.NewFromConfig(c.cfg).ListTagsForResource(ctx, &inspector2.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *inspector2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
