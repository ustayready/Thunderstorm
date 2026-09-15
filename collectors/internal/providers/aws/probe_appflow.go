package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appflow"
)

func init() {
	registerFetcher("DescribeFlow", "aws:appflow:flow", fetchAppflowDescribeFlow)
	registerFetcher("ListTagsForResource", "aws:appflow:flow", fetchAppflowListTagsForResource)
}

// Exposure probe: aws-appflow-flow-task-connector-properties (DescribeFlow -> sourceFlowConfig / destinationFlowConfigList[] / tasks[]).
func fetchAppflowDescribeFlow(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := appflow.NewFromConfig(c.cfg).DescribeFlow(ctx, &appflow.DescribeFlowInput{
		FlowName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *appflow.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-appflow-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchAppflowListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := appflow.NewFromConfig(c.cfg).ListTagsForResource(ctx, &appflow.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *appflow.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
