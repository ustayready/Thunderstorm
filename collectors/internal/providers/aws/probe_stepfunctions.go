package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

func init() {
	registerFetcher("DescribeStateMachine", "aws:stepfunctions:state_machine", fetchStepfunctionsDescribeStateMachine)
	registerFetcher("ListTagsForResource", "aws:stepfunctions:state_machine", fetchStepfunctionsListTagsForResource)
}

// Exposure probe: aws-stepfunctions-state-machine-definition (DescribeStateMachine -> definition).
func fetchStepfunctionsDescribeStateMachine(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sfn.NewFromConfig(c.cfg).DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *sfn.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-stepfunctions-resource-tags-value-config (ListTagsForResource -> tags[].value).
func fetchStepfunctionsListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sfn.NewFromConfig(c.cfg).ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *sfn.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
