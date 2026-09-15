package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

func init() {
	registerFetcher("DescribeNotebookInstanceLifecycleConfig", "aws:sagemaker:notebook-lifecycle-config", fetchSageMakerDescribeNotebookInstanceLifecycleConfigExt)
	registerFetcher("DescribeStudioLifecycleConfig", "aws:sagemaker:studio-lifecycle-config", fetchSageMakerDescribeStudioLifecycleConfigExt)
	registerFetcher("DescribeModel", "aws:sagemaker:model", fetchSageMakerDescribeModelExt)
	registerFetcher("DescribeTrainingJob", "aws:sagemaker:training-job", fetchSageMakerDescribeTrainingJobExt)
	registerFetcher("DescribeProcessingJob", "aws:sagemaker:processing-job", fetchSageMakerDescribeProcessingJobExt)
	registerFetcher("DescribeTransformJob", "aws:sagemaker:transform-job", fetchSageMakerDescribeTransformJobExt)
	registerFetcher("DescribePipeline", "aws:sagemaker:pipeline", fetchSageMakerDescribePipelineExt)
}

// fetchSageMakerDescribeNotebookInstanceLifecycleConfigExt fetches the full lifecycle
// configuration for a SageMaker notebook instance lifecycle config, including the
// base64-encoded OnCreate and OnStart shell scripts that may contain credentials.
// Exposure probe: aws-sagemaker-notebook-lifecycle-content
// (DescribeNotebookInstanceLifecycleConfig -> OnCreate[].Content / OnStart[].Content).
func fetchSageMakerDescribeNotebookInstanceLifecycleConfigExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribeNotebookInstanceLifecycleConfig(ctx, &sagemaker.DescribeNotebookInstanceLifecycleConfigInput{
		NotebookInstanceLifecycleConfigName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSageMakerDescribeStudioLifecycleConfigExt fetches the full Studio lifecycle
// configuration including the base64-encoded script content that may contain
// credentials installed into every user or app environment.
// Exposure probe: aws-sagemaker-studio-lifecycle-content
// (DescribeStudioLifecycleConfig -> StudioLifecycleConfigContent).
func fetchSageMakerDescribeStudioLifecycleConfigExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribeStudioLifecycleConfig(ctx, &sagemaker.DescribeStudioLifecycleConfigInput{
		StudioLifecycleConfigName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSageMakerDescribeModelExt fetches the full model description including
// primary container and inference container environment maps that may contain
// plaintext credentials or connection strings.
// Exposure probe: aws-sagemaker-model-container-environment
// (DescribeModel -> PrimaryContainer.Environment / Containers[].Environment).
func fetchSageMakerDescribeModelExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribeModel(ctx, &sagemaker.DescribeModelInput{
		ModelName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSageMakerDescribeTrainingJobExt fetches the full training job description
// including the environment and hyperparameter maps that may contain plaintext
// credentials or proprietary configuration.
// Exposure probe: aws-sagemaker-training-job-environment-hyperparameters
// (DescribeTrainingJob -> Environment / HyperParameters).
func fetchSageMakerDescribeTrainingJobExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribeTrainingJob(ctx, &sagemaker.DescribeTrainingJobInput{
		TrainingJobName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSageMakerDescribeProcessingJobExt fetches the full processing job description
// including the environment map that may expose data-source credentials.
// Exposure probe: aws-sagemaker-processing-job-environment
// (DescribeProcessingJob -> Environment).
func fetchSageMakerDescribeProcessingJobExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribeProcessingJob(ctx, &sagemaker.DescribeProcessingJobInput{
		ProcessingJobName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSageMakerDescribeTransformJobExt fetches the full batch-transform job description
// including the environment map that may expose data-source credentials.
// Exposure probe: aws-sagemaker-transform-job-environment
// (DescribeTransformJob -> Environment).
func fetchSageMakerDescribeTransformJobExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribeTransformJob(ctx, &sagemaker.DescribeTransformJobInput{
		TransformJobName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSageMakerDescribePipelineExt fetches the full pipeline description including
// the PipelineDefinition JSON document that may hard-code credentials, environment
// variables, commands, and data locations.
// Exposure probe: aws-sagemaker-pipeline-definition
// (DescribePipeline -> PipelineDefinition).
func fetchSageMakerDescribePipelineExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := sagemaker.NewFromConfig(c.cfg).DescribePipeline(ctx, &sagemaker.DescribePipelineInput{
		PipelineName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *sagemaker.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
