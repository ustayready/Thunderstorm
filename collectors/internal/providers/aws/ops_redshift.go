package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

func init() { register("redshift:DescribeClusters", opRedshiftDescribeClusters) }

// opRedshiftDescribeClusters enumerates Redshift clusters (read-only).
func opRedshiftDescribeClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := redshift.NewFromConfig(c.cfg)
	p := redshift.NewDescribeClustersPaginator(svc, &redshift.DescribeClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *redshift.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Clusters {
			recs = append(recs, Record{
				"cluster_identifier": aws.ToString(item.ClusterIdentifier),
			})
		}
	}
	return recs, nil
}
