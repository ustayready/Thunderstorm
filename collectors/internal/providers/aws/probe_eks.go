package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func init() {
	registerFetcher("DescribeCluster", "aws:eks:cluster", fetchEksDescribeCluster)
}

// Exposure probe: aws-eks-cluster-tags-value-config (DescribeCluster -> cluster.tags.<value>).
func fetchEksDescribeCluster(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := eks.NewFromConfig(c.cfg).DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *eks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
