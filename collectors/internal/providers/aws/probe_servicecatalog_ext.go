package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
)

func init() {
	registerFetcher("DescribeRecord", "aws:servicecatalog:portfolio", fetchServiceCatalogDescribeRecordExt)
}

// Exposure probe: aws-servicecatalog-provisioned-product-record-output
// (DescribeRecord -> RecordOutputs[].OutputValue).
//
// DescribeRecord requires a record ID that is a sub-resource of provisioned
// products, not of portfolios. We enumerate all record IDs account-wide using
// ListRecordHistory (no required parent ID) and then call DescribeRecord for
// each one. The portfolio item is used only as an execution anchor, identical to
// how ListTagOptions is anchored.
func fetchServiceCatalogDescribeRecordExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := servicecatalog.NewFromConfig(c.cfg)
	opt := func(o *servicecatalog.Options) { o.Region = region }

	// Enumerate all record IDs visible to the caller.
	var recordIDs []string
	var pageToken *string
	for {
		out, err := svc.ListRecordHistory(ctx, &servicecatalog.ListRecordHistoryInput{
			PageToken: pageToken,
		}, opt)
		if err != nil {
			return nil, err
		}
		for _, rd := range out.RecordDetails {
			if rd.RecordId != nil {
				recordIDs = append(recordIDs, *rd.RecordId)
			}
		}
		if out.NextPageToken == nil {
			break
		}
		pageToken = out.NextPageToken
	}

	// Call DescribeRecord for each record and accumulate outputs.
	results := make([]any, 0, len(recordIDs))
	for _, id := range recordIDs {
		id := id
		rec, err := svc.DescribeRecord(ctx, &servicecatalog.DescribeRecordInput{
			Id: &id,
		}, opt)
		if err != nil {
			// A single inaccessible record should not abort the whole sweep.
			continue
		}
		results = append(results, jsonify(rec))
	}

	return jsonify(map[string]any{"Records": results}), nil
}
