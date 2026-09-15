package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
)

func init() { register("servicecatalog:ListPortfolios", opServiceCatalogListPortfolios) }

// opServiceCatalogListPortfolios enumerates Service Catalog portfolios (read-only).
func opServiceCatalogListPortfolios(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := servicecatalog.NewFromConfig(c.cfg)
	p := servicecatalog.NewListPortfoliosPaginator(svc, &servicecatalog.ListPortfoliosInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *servicecatalog.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, portfolio := range out.PortfolioDetails {
			recs = append(recs, Record{
				"portfolio_id": aws.ToString(portfolio.Id),
				"arn":          aws.ToString(portfolio.ARN),
			})
		}
	}
	return recs, nil
}
