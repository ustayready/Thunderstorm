package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog/types"
)

func init() {
	registerFetcher("ListTagOptions", "aws:servicecatalog:portfolio", fetchServiceCatalogListTagOptions)
}

// Exposure probe: aws-servicecatalog-tag-option-value-config (ListTagOptions -> TagOptionDetails[].Value).
// ListTagOptions is account-wide; the portfolio item is used only as an execution anchor.
func fetchServiceCatalogListTagOptions(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := servicecatalog.NewFromConfig(c.cfg).ListTagOptions(ctx, &servicecatalog.ListTagOptionsInput{
		Filters: &types.ListTagOptionsFilters{
			Active: aws.Bool(true),
		},
	}, func(o *servicecatalog.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
