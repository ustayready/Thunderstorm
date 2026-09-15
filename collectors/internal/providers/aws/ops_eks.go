package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func init() { register("eks:ListClusters", opEKSListClusters) }

// opEKSListClusters enumerates EKS clusters (read-only).
func opEKSListClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := eks.NewFromConfig(c.cfg)
	p := eks.NewListClustersPaginator(svc, &eks.ListClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *eks.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, name := range out.Clusters {
			recs = append(recs, Record{
				"cluster_name": name,
			})
		}
	}
	return recs, nil
}
