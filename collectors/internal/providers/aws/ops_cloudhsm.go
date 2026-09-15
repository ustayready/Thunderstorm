package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
)

func init() { register("cloudhsm:DescribeClusters", opCloudHSMDescribeClusters) }

// opCloudHSMDescribeClusters enumerates CloudHSM v2 clusters (read-only).
func opCloudHSMDescribeClusters(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := cloudhsmv2.NewFromConfig(c.cfg)
	p := cloudhsmv2.NewDescribeClustersPaginator(svc, &cloudhsmv2.DescribeClustersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *cloudhsmv2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, cluster := range out.Clusters {
			recs = append(recs, Record{
				"cluster_id": aws.ToString(cluster.ClusterId),
			})
		}
	}
	return recs, nil
}
