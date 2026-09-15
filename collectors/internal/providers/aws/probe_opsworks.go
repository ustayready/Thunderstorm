package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opsworks"
)

func init() {
	registerFetcher("DescribeStacks", "aws:opsworks:stack", fetchOpsworksDescribeStacks)
	registerFetcher("DescribeRdsDbInstances", "aws:opsworks:stack", fetchOpsworksDescribeRdsDbInstances)
	registerFetcher("ListTags", "aws:opsworks:stack", fetchOpsworksListTags)
}

// Exposure probe: aws-opsworks-stack-custom-json (DescribeStacks -> Stacks[].CustomJson).
func fetchOpsworksDescribeStacks(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opsworks.NewFromConfig(c.cfg).DescribeStacks(ctx, &opsworks.DescribeStacksInput{
		StackIds: []string{itemStr(item, "native_id", "arn")},
	}, func(o *opsworks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-opsworks-registered-rds-password (DescribeRdsDbInstances -> RdsDbInstances[].DbPassword).
func fetchOpsworksDescribeRdsDbInstances(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opsworks.NewFromConfig(c.cfg).DescribeRdsDbInstances(ctx, &opsworks.DescribeRdsDbInstancesInput{
		StackId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *opsworks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-opsworks-resource-tags-value-config (ListTags -> Tags.<value>).
func fetchOpsworksListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opsworks.NewFromConfig(c.cfg).ListTags(ctx, &opsworks.ListTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *opsworks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
