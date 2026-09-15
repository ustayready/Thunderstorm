package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
)

func init() {
	registerFetcher("DescribeDashboardDefinition", "aws:quicksight:dashboard", fetchQuickSightDescribeDashboardDefinition)
	registerFetcher("ListTagsForResource", "aws:quicksight:dashboard", fetchQuickSightListTagsForResource)
}

// Exposure probe: aws-quicksight-dashboard-definition-values (DescribeDashboardDefinition -> Definition).
func fetchQuickSightDescribeDashboardDefinition(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	id, err := c.CallerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	out, err := quicksight.NewFromConfig(c.cfg).DescribeDashboardDefinition(ctx, &quicksight.DescribeDashboardDefinitionInput{
		AwsAccountId: aws.String(id.Account),
		DashboardId:  aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *quicksight.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-quicksight-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchQuickSightListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := quicksight.NewFromConfig(c.cfg).ListTagsForResource(ctx, &quicksight.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *quicksight.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
