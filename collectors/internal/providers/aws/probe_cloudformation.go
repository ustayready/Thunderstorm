package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func init() {
	registerFetcher("DescribeStacks", "aws:cloudformation:stack", fetchCloudFormationDescribeStacks)
	registerFetcher("GetTemplate", "aws:cloudformation:stack", fetchCloudFormationGetTemplate)
	registerFetcher("DescribeStackEvents", "aws:cloudformation:stack", fetchCloudFormationDescribeStackEvents)
}

// Exposure probe: aws-cloudformation-stack-parameter-value / aws-cloudformation-stack-output-value /
// aws-cloudformation-stack-tags-value-config (DescribeStacks -> Stacks[].Parameters[].ParameterValue,
// Stacks[].Outputs[].OutputValue, Stacks[].Tags[].Value).
func fetchCloudFormationDescribeStacks(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudformation.NewFromConfig(c.cfg).DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
		StackName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cloudformation.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-cloudformation-template-body-metadata-and-defaults
// (GetTemplate -> TemplateBody).
func fetchCloudFormationGetTemplate(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudformation.NewFromConfig(c.cfg).GetTemplate(ctx, &cloudformation.GetTemplateInput{
		StackName:     aws.String(itemStr(item, "native_id", "arn")),
		TemplateStage: types.TemplateStageOriginal,
	}, func(o *cloudformation.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-cloudformation-stack-event-status-reason
// (DescribeStackEvents -> StackEvents[].ResourceStatusReason).
func fetchCloudFormationDescribeStackEvents(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudformation.NewFromConfig(c.cfg).DescribeStackEvents(ctx, &cloudformation.DescribeStackEventsInput{
		StackName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cloudformation.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
