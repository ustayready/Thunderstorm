package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
)

// Exposure probe: aws-msk-cluster-configuration-properties
// (DescribeConfigurationRevision -> ServerProperties).
//
// The cluster item carries only its own ARN; the configuration ARN and revision
// are fetched by first calling DescribeClusterV2 on the cluster, then using the
// ConfigurationArn / ConfigurationRevision from
// ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.
func init() {
	registerFetcher("DescribeConfigurationRevision", "aws:msk:cluster", fetchMskDescribeConfigurationRevisionExt)
}

func fetchMskDescribeConfigurationRevisionExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := kafka.NewFromConfig(c.cfg, func(o *kafka.Options) { o.Region = region })

	clusterArn := itemStr(item, "arn", "native_id")
	if clusterArn == "" {
		return nil, fmt.Errorf("msk: item has no arn/native_id")
	}

	// Step 1: resolve the configuration ARN and revision from the cluster.
	desc, err := svc.DescribeClusterV2(ctx, &kafka.DescribeClusterV2Input{
		ClusterArn: aws.String(clusterArn),
	})
	if err != nil {
		return nil, err
	}

	if desc.ClusterInfo == nil || desc.ClusterInfo.Provisioned == nil {
		return nil, fmt.Errorf("msk: cluster %s is not a provisioned cluster or has no broker software info", clusterArn)
	}

	bsi := desc.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo
	if bsi == nil || bsi.ConfigurationArn == nil || bsi.ConfigurationRevision == nil {
		return nil, fmt.Errorf("msk: cluster %s has no associated MSK configuration", clusterArn)
	}

	// Step 2: fetch the configuration revision (contains ServerProperties).
	out, err := svc.DescribeConfigurationRevision(ctx, &kafka.DescribeConfigurationRevisionInput{
		Arn:      bsi.ConfigurationArn,
		Revision: bsi.ConfigurationRevision,
	})
	if err != nil {
		return nil, err
	}

	return jsonify(out), nil
}
