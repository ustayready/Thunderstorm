package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() {
	registerFetcher("DescribeDBClusterParameters", "aws:documentdb:db_cluster", fetchDocumentDBDescribeDBClusterParametersExt)
}

// fetchDocumentDBDescribeDBClusterParametersExt implements the exposure probe for
// aws-documentdb-cluster-parameter-value-config
// (DescribeDBClusterParameters -> Parameters[].ParameterValue).
//
// DescribeDBClusterParameters requires a DBClusterParameterGroupName, not the
// cluster identifier. We resolve the group name with a DescribeDBClusters call
// keyed by the inventory item's native_id, then fetch all parameter pages.
func fetchDocumentDBDescribeDBClusterParametersExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	clusterID := itemStr(item, "native_id", "arn")
	svc := rds.NewFromConfig(c.cfg)
	optFn := func(o *rds.Options) { o.Region = region }

	// Step 1: resolve the parameter group name from the cluster.
	descOut, err := svc.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(clusterID),
	}, optFn)
	if err != nil {
		return nil, fmt.Errorf("DescribeDBClusters: %w", err)
	}
	if len(descOut.DBClusters) == 0 || descOut.DBClusters[0].DBClusterParameterGroup == nil {
		return nil, nil
	}
	pgName := *descOut.DBClusters[0].DBClusterParameterGroup

	// Step 2: fetch all parameter pages for the resolved group.
	var allParams []any
	var marker *string
	for {
		pgOut, err := svc.DescribeDBClusterParameters(ctx, &rds.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: aws.String(pgName),
			Marker:                      marker,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("DescribeDBClusterParameters: %w", err)
		}
		allParams = append(allParams, jsonify(pgOut))
		if pgOut.Marker == nil {
			break
		}
		marker = pgOut.Marker
	}

	return allParams, nil
}
