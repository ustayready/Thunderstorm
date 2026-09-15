package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
)

func init() { register("account:ListRegions", opAccountListRegions) }

// opAccountListRegions enumerates regions enabled for the current AWS account (read-only).
func opAccountListRegions(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := account.NewFromConfig(c.cfg)
	p := account.NewListRegionsPaginator(svc, &account.ListRegionsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *account.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Regions {
			recs = append(recs, Record{
				"region_name": aws.ToString(item.RegionName),
			})
		}
	}
	return recs, nil
}
