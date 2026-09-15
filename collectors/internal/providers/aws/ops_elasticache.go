package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

func init() { register("elasticache:DescribeCacheClusters", opElastiCacheDescribeCacheClusters) }

// opElastiCacheDescribeCacheClusters enumerates ElastiCache cache clusters (read-only).
func opElastiCacheDescribeCacheClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := elasticache.NewFromConfig(c.cfg)
	p := elasticache.NewDescribeCacheClustersPaginator(svc, &elasticache.DescribeCacheClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *elasticache.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.CacheClusters {
			recs = append(recs, Record{
				"cache_cluster_id": aws.ToString(item.CacheClusterId),
				"arn":              aws.ToString(item.ARN),
			})
		}
	}
	return recs, nil
}
