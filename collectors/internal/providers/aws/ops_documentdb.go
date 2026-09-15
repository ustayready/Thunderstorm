package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() { register("documentdb:DescribeDBClusters", opDocumentDBDescribeDBClusters) }

// opDocumentDBDescribeDBClusters enumerates DocumentDB clusters (read-only).
func opDocumentDBDescribeDBClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := rds.NewFromConfig(c.cfg)
	p := rds.NewDescribeDBClustersPaginator(svc, &rds.DescribeDBClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *rds.Options) { o.Region = region })
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
