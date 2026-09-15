package aws

// Exposure probes for additional Redshift read-API operations.
//
// Already implemented in probe_redshift.go:
//   - DescribeTags (aws-redshift-resource-tags-value-config)
//
// This file adds:
//   - DescribeClusterParameters (aws-redshift-cluster-parameter-value-config):
//     requires ParameterGroupName, which is resolved by first calling
//     DescribeClusters with the cluster identifier to enumerate attached groups.
//   - DescribeLoggingStatus: secondary op keyed by ClusterIdentifier that
//     exposes S3 bucket names, prefixes, and logging config.
//   - GetResourcePolicy: secondary op keyed by the cluster ARN that exposes
//     the resource-based IAM policy attached to the cluster.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

func init() {
	registerFetcher("DescribeClusterParameters", "aws:redshift:cluster", fetchRedshiftDescribeClusterParametersExt)
	registerFetcher("DescribeLoggingStatus", "aws:redshift:cluster", fetchRedshiftDescribeLoggingStatusExt)
	registerFetcher("GetResourcePolicy", "aws:redshift:cluster", fetchRedshiftGetResourcePolicyExt)
}

// fetchRedshiftDescribeClusterParametersExt implements the exposure probe for
// aws-redshift-cluster-parameter-value-config (DescribeClusterParameters ->
// Parameters[].ParameterValue).
//
// The inventory native_id is the ClusterIdentifier. DescribeClusterParameters
// requires a ParameterGroupName, so we first call DescribeClusters to retrieve
// the list of attached parameter groups, then fetch parameters for each one and
// return them aggregated under a top-level "ParameterGroups" key.
func fetchRedshiftDescribeClusterParametersExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := redshift.NewFromConfig(c.cfg)
	ro := func(o *redshift.Options) { o.Region = region }

	clusterID := itemStr(item, "native_id", "arn")

	// Resolve the parameter groups attached to this cluster.
	clusterOut, err := svc.DescribeClusters(ctx, &redshift.DescribeClustersInput{
		ClusterIdentifier: aws.String(clusterID),
	}, ro)
	if err != nil {
		return nil, fmt.Errorf("DescribeClusters(%s): %w", clusterID, err)
	}
	if len(clusterOut.Clusters) == 0 {
		return nil, fmt.Errorf("cluster %s not found", clusterID)
	}

	// Collect parameter group names from the first (and only) matching cluster.
	cluster := clusterOut.Clusters[0]
	var paramGroupNames []string
	for _, pg := range cluster.ClusterParameterGroups {
		if pg.ParameterGroupName != nil && *pg.ParameterGroupName != "" {
			paramGroupNames = append(paramGroupNames, *pg.ParameterGroupName)
		}
	}

	// Fetch parameters for each group.
	var groups []any
	for _, pgName := range paramGroupNames {
		var params []any
		var marker *string
		for {
			out, err := svc.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{
				ParameterGroupName: aws.String(pgName),
				Marker:             marker,
			}, ro)
			if err != nil {
				// Non-fatal: skip inaccessible groups.
				break
			}
			for _, p := range out.Parameters {
				params = append(params, jsonify(p))
			}
			if out.Marker == nil {
				break
			}
			marker = out.Marker
		}
		groups = append(groups, map[string]any{
			"ParameterGroupName": pgName,
			"Parameters":         params,
		})
	}

	return map[string]any{"ParameterGroups": groups}, nil
}

// fetchRedshiftDescribeLoggingStatusExt implements a secondary exposure probe
// for DescribeLoggingStatus -> BucketName / S3KeyPrefix / LogDestinationType.
//
// Logging config can expose S3 bucket names used for audit logs; the bucket
// name and prefix are plaintext and may be sensitive.
func fetchRedshiftDescribeLoggingStatusExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := redshift.NewFromConfig(c.cfg).DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
		ClusterIdentifier: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *redshift.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchRedshiftGetResourcePolicyExt implements a secondary exposure probe for
// GetResourcePolicy -> ResourcePolicy.Policy (IAM resource-based policy JSON).
//
// Resource policies on Redshift clusters can contain principal ARNs, condition
// keys, and other security-sensitive configuration.
func fetchRedshiftGetResourcePolicyExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := redshift.NewFromConfig(c.cfg).GetResourcePolicy(ctx, &redshift.GetResourcePolicyInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *redshift.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
