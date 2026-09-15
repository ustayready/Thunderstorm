package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
)

func init() {
	registerFetcher("DescribeDataSet", "aws:quicksight:dataset", fetchQuickSightDescribeDataSetExt)
	registerFetcher("DescribeAnalysisDefinition", "aws:quicksight:analysis", fetchQuickSightDescribeAnalysisDefinitionExt)
}

// Exposure probe: aws-quicksight-dataset-custom-sql (DescribeDataSet -> DataSet.PhysicalTableMap.<id>.CustomSql.SqlQuery).
func fetchQuickSightDescribeDataSetExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	id, err := c.CallerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	out, err := quicksight.NewFromConfig(c.cfg).DescribeDataSet(ctx, &quicksight.DescribeDataSetInput{
		AwsAccountId: aws.String(id.Account),
		DataSetId:    aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *quicksight.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-quicksight-analysis-definition-values (DescribeAnalysisDefinition -> Definition).
func fetchQuickSightDescribeAnalysisDefinitionExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	id, err := c.CallerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	out, err := quicksight.NewFromConfig(c.cfg).DescribeAnalysisDefinition(ctx, &quicksight.DescribeAnalysisDefinitionInput{
		AwsAccountId: aws.String(id.Account),
		AnalysisId:   aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *quicksight.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
