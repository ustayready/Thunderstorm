package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func init() {
	registerFetcher("DescribeTaskDefinition", "aws:ecs:task_definition", fetchEcsDescribeTaskDefinitionExt)
	registerFetcher("DescribeTasks", "aws:ecs:task", fetchEcsDescribeTasksExt)
}

// Exposure probe: aws-ecs-task-definition-environment-value,
// aws-ecs-task-definition-command-arguments, aws-ecs-task-log-driver-options-config,
// aws-ecs-task-definition-docker-label-value (DescribeTaskDefinition -> taskDefinition.*).
// native_id is the task definition ARN or family:revision string.
func fetchEcsDescribeTaskDefinitionExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ecs.NewFromConfig(c.cfg).DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(itemStr(item, "arn", "native_id")),
		Include:        []types.TaskDefinitionField{types.TaskDefinitionFieldTags},
	}, func(o *ecs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ecs-running-task-overrides
// (DescribeTasks -> tasks[].overrides.containerOverrides[].{environment[].value,command}).
// native_id is the task ARN; optional cluster attribute provides the cluster ARN/name.
func fetchEcsDescribeTasksExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	input := &ecs.DescribeTasksInput{
		Tasks:   []string{itemStr(item, "arn", "native_id")},
		Include: []types.TaskField{types.TaskFieldTags},
	}
	if cluster := itemStr(item, "cluster", "cluster_arn"); cluster != "" {
		input.Cluster = aws.String(cluster)
	}
	out, err := ecs.NewFromConfig(c.cfg).DescribeTasks(ctx, input,
		func(o *ecs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
