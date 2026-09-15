package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
)

func init() {
	registerFetcher("DescribeCluster", "aws:emr:cluster", fetchEMRDescribeCluster)
	registerFetcher("ListBootstrapActions", "aws:emr:cluster", fetchEMRListBootstrapActions)
}

// Exposure probe: aws-emr-cluster-configuration-properties + aws-emr-resource-tags-value-config
// (DescribeCluster -> Cluster.Configurations[].Properties / Cluster.Tags[].Value).
func fetchEMRDescribeCluster(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := emr.NewFromConfig(c.cfg).DescribeCluster(ctx, &emr.DescribeClusterInput{
		ClusterId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *emr.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-emr-bootstrap-action-arguments (ListBootstrapActions -> BootstrapActions[].Args).
func fetchEMRListBootstrapActions(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := emr.NewFromConfig(c.cfg).ListBootstrapActions(ctx, &emr.ListBootstrapActionsInput{
		ClusterId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *emr.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
