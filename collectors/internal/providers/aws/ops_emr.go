package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
)

func init() { register("elasticmapreduce:ListClusters", opEMRListClusters) }

// opEMRListClusters enumerates EMR clusters (read-only).
func opEMRListClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := emr.NewFromConfig(c.cfg)
	p := emr.NewListClustersPaginator(svc, &emr.ListClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *emr.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Clusters {
			recs = append(recs, Record{
				"cluster_id": aws.ToString(item.Id),
				"arn":        aws.ToString(item.ClusterArn),
			})
		}
	}
	return recs, nil
}
