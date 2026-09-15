package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation/types"
)

func init() {
	registerFetcher("ListLFTags", "aws:lakeformation:resource", fetchLakeFormationListLFTags)
	registerFetcher("GetDataLakeSettings", "aws:lakeformation:resource", fetchLakeFormationGetDataLakeSettings)
}

// Exposure probe: aws-lakeformation-lf-tag-values-config (ListLFTags -> LFTags[].TagValues[]).
// CatalogId is omitted so the call targets the identity's own account (catalog).
// ResourceShareType ALL is set per the site's static params to include shared tags.
func fetchLakeFormationListLFTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lakeformation.NewFromConfig(c.cfg).ListLFTags(ctx, &lakeformation.ListLFTagsInput{
		ResourceShareType: types.ResourceShareTypeAll,
	}, func(o *lakeformation.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-lakeformation-data-lake-settings-parameters (GetDataLakeSettings -> DataLakeSettings.Parameters.<value>).
// CatalogId is omitted so the call targets the identity's own account (catalog).
func fetchLakeFormationGetDataLakeSettings(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lakeformation.NewFromConfig(c.cfg).GetDataLakeSettings(ctx, &lakeformation.GetDataLakeSettingsInput{},
		func(o *lakeformation.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
