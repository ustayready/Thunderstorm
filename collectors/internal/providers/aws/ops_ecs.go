package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

func init() { register("ecs:ListClusters", opECSListClusters) }

// opECSListClusters enumerates ECS clusters (read-only).
func opECSListClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ecs.NewFromConfig(c.cfg)
	p := ecs.NewListClustersPaginator(svc, &ecs.ListClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ecs.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, arn := range out.ClusterArns {
			recs = append(recs, Record{
				"cluster_arn": arn,
			})
		}
	}
	return recs, nil
}
