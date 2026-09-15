package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func init() { register("cloudfront:ListDistributions", opCloudfrontListDistributions) }

// opCloudfrontListDistributions enumerates CloudFront distributions (read-only).
func opCloudfrontListDistributions(ctx context.Context, c *Client, _ string, _ map[string]string) ([]Record, error) {
	svc := cloudfront.NewFromConfig(c.cfg)
	p := cloudfront.NewListDistributionsPaginator(svc, &cloudfront.ListDistributionsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if out.DistributionList == nil {
			continue
		}
		for _, d := range out.DistributionList.Items {
			recs = append(recs, Record{
				"distribution_id": aws.ToString(d.Id),
				"arn":             aws.ToString(d.ARN),
			})
		}
	}
	return recs, nil
}
