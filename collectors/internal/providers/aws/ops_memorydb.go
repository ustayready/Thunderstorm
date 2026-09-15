package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
)

func init() { register("memorydb:DescribeClusters", opMemoryDBDescribeClusters) }

// opMemoryDBDescribeClusters enumerates MemoryDB clusters (read-only).
func opMemoryDBDescribeClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := memorydb.NewFromConfig(c.cfg)
	p := memorydb.NewDescribeClustersPaginator(svc, &memorydb.DescribeClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *memorydb.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Clusters {
			recs = append(recs, Record{
				"cluster_name": aws.ToString(item.Name),
				"arn":          aws.ToString(item.ARN),
			})
		}
	}
	return recs, nil
}
