package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
)

func init() {
	registerFetcher("GetCustomModel", "aws:bedrock:custom_model", fetchBedrockGetCustomModelExt)
	registerFetcher("GetModelInvocationLoggingConfiguration", "aws:bedrock:custom_model", fetchBedrockGetModelInvocationLoggingConfigurationExt)
	registerFetcher("GetResourcePolicy", "aws:bedrock:custom_model", fetchBedrockGetResourcePolicyExt)
}

// fetchBedrockGetCustomModelExt fetches full detail for a custom model by its
// name or ARN. This surfaces training configuration, hyperparameters, and
// output S3 paths that may contain sensitive values.
func fetchBedrockGetCustomModelExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := bedrock.NewFromConfig(c.cfg).GetCustomModel(ctx, &bedrock.GetCustomModelInput{
		ModelIdentifier: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *bedrock.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchBedrockGetModelInvocationLoggingConfigurationExt fetches the account-level
// model invocation logging configuration, which exposes S3 bucket names,
// CloudWatch log-group names, and encryption key ARNs for the logging destination.
// This is an account-scoped call; the inventory item is used only to scope the
// call to the correct region.
func fetchBedrockGetModelInvocationLoggingConfigurationExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := bedrock.NewFromConfig(c.cfg).GetModelInvocationLoggingConfiguration(ctx,
		&bedrock.GetModelInvocationLoggingConfigurationInput{},
		func(o *bedrock.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchBedrockGetResourcePolicyExt fetches the resource-based policy document
// attached to a Bedrock custom model. Resource policies can contain cross-account
// principal grants and condition keys that expose sensitive configuration.
func fetchBedrockGetResourcePolicyExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := bedrock.NewFromConfig(c.cfg).GetResourcePolicy(ctx, &bedrock.GetResourcePolicyInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *bedrock.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
