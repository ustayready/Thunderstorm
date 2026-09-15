package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
)

func init() {
	registerFetcher("GetPipeline", "aws:codepipeline:pipeline", fetchCodePipelineGetPipeline)
	registerFetcher("ListActionExecutions", "aws:codepipeline:pipeline", fetchCodePipelineListActionExecutions)
	registerFetcher("ListTagsForResource", "aws:codepipeline:pipeline", fetchCodePipelineListTagsForResource)
}

// Exposure probe: aws-codepipeline-action-configuration-values, aws-codepipeline-pipeline-variable-default
// (GetPipeline -> pipeline.stages[].actions[].configuration.<value>, pipeline.variables[].defaultValue).
func fetchCodePipelineGetPipeline(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codepipeline.NewFromConfig(c.cfg).GetPipeline(ctx, &codepipeline.GetPipelineInput{
		Name: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *codepipeline.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-codepipeline-action-output-variables, aws-codepipeline-action-execution-summary
// (ListActionExecutions -> actionExecutionDetails[].output.outputVariables.<value>,
// actionExecutionDetails[].output.executionResult.externalExecutionSummary).
func fetchCodePipelineListActionExecutions(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codepipeline.NewFromConfig(c.cfg).ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{
		PipelineName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *codepipeline.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-codepipeline-pipeline-tags-value-config (ListTagsForResource -> tags[].value).
func fetchCodePipelineListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codepipeline.NewFromConfig(c.cfg).ListTagsForResource(ctx, &codepipeline.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *codepipeline.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
