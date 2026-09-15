package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
)

func init() { register("quicksight:ListDashboards", opQuickSightListDashboards) }

// opQuickSightListDashboards enumerates QuickSight dashboards (read-only).
func opQuickSightListDashboards(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	id, err := c.CallerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	svc := quicksight.NewFromConfig(c.cfg)
	p := quicksight.NewListDashboardsPaginator(svc, &quicksight.ListDashboardsInput{
		AwsAccountId: aws.String(id.Account),
	})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *quicksight.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, d := range out.DashboardSummaryList {
			recs = append(recs, Record{
				"dashboard_id": aws.ToString(d.DashboardId),
				"arn":          aws.ToString(d.Arn),
			})
		}
	}
	return recs, nil
}
