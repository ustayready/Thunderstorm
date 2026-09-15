package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
)

func init() { register("msk:ListClustersV2", opMSKListClustersV2) }

// opMSKListClustersV2 enumerates MSK (Kafka) clusters (read-only).
func opMSKListClustersV2(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := kafka.NewFromConfig(c.cfg)
	p := kafka.NewListClustersV2Paginator(svc, &kafka.ListClustersV2Input{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *kafka.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, cl := range out.ClusterInfoList {
			recs = append(recs, Record{
				"cluster_name": aws.ToString(cl.ClusterName),
				"cluster_arn":  aws.ToString(cl.ClusterArn),
			})
		}
	}
	return recs, nil
}
