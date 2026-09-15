package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datapipeline"
)

func init() {
	registerFetcher("GetPipelineDefinition", "aws:datapipeline:pipeline", fetchDatapipelineGetPipelineDefinition)
	registerFetcher("DescribePipelines", "aws:datapipeline:pipeline", fetchDatapipelineDescribePipelines)
}

// Exposure probe: aws-datapipeline-pipeline-object-field-values + aws-datapipeline-pipeline-parameter-values
// (GetPipelineDefinition -> pipelineObjects[].fields[].{stringValue,refValue} / parameterValues[].stringValue).
func fetchDatapipelineGetPipelineDefinition(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := datapipeline.NewFromConfig(c.cfg).GetPipelineDefinition(ctx, &datapipeline.GetPipelineDefinitionInput{
		PipelineId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *datapipeline.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-datapipeline-pipeline-tags-value-config
// (DescribePipelines -> pipelineDescriptionList[].tags[].value).
func fetchDatapipelineDescribePipelines(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := datapipeline.NewFromConfig(c.cfg).DescribePipelines(ctx, &datapipeline.DescribePipelinesInput{
		PipelineIds: []string{itemStr(item, "native_id", "arn")},
	}, func(o *datapipeline.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
