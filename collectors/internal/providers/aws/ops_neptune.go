package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
)

func init() { register("neptune:DescribeDBClusters", opNeptuneDescribeDBClusters) }

// opNeptuneDescribeDBClusters enumerates Neptune DB clusters (read-only).
func opNeptuneDescribeDBClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := neptune.NewFromConfig(c.cfg)
	p := neptune.NewDescribeDBClustersPaginator(svc, &neptune.DescribeDBClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *neptune.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.DBClusters {
			recs = append(recs, Record{
				"db_cluster_identifier": aws.ToString(item.DBClusterIdentifier),
				"arn":                   aws.ToString(item.DBClusterArn),
			})
		}
	}
	return recs, nil
}
