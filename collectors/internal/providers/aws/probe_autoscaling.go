package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

func init() {
	registerFetcher("DescribeAutoScalingGroups", "aws:autoscaling:auto-scaling-group", fetchAutoscalingDescribeAutoScalingGroups)
	registerFetcher("DescribeLifecycleHooks", "aws:autoscaling:auto-scaling-group", fetchAutoscalingDescribeLifecycleHooks)
}

// Exposure probe: aws-autoscaling-group-tags-value-config (DescribeAutoScalingGroups -> AutoScalingGroups[].Tags[].Value).
func fetchAutoscalingDescribeAutoScalingGroups(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := autoscaling.NewFromConfig(c.cfg).DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{itemStr(item, "native_id", "arn")},
	}, func(o *autoscaling.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-autoscaling-lifecycle-hook-notification-metadata (DescribeLifecycleHooks -> LifecycleHooks[].NotificationMetadata).
func fetchAutoscalingDescribeLifecycleHooks(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := autoscaling.NewFromConfig(c.cfg).DescribeLifecycleHooks(ctx, &autoscaling.DescribeLifecycleHooksInput{
		AutoScalingGroupName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *autoscaling.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
