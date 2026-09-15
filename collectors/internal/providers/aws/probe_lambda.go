package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func init() {
	registerFetcher("GetFunctionConfiguration", "aws:lambda:function", fetchLambdaGetFunctionConfiguration)
	registerFetcher("GetFunction", "aws:lambda:function", fetchLambdaGetFunction)
	registerFetcher("ListTags", "aws:lambda:function", fetchLambdaListTags)
}

// Exposure probe: aws-lambda-environment-variables-config (GetFunctionConfiguration -> Environment.Variables.<value>).
func fetchLambdaGetFunctionConfiguration(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lambda.NewFromConfig(c.cfg).GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *lambda.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-lambda-deployment-package-code (GetFunction -> Code.Location).
func fetchLambdaGetFunction(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lambda.NewFromConfig(c.cfg).GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *lambda.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-lambda-resource-tags-value-config (ListTags -> Tags.<value>).
func fetchLambdaListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lambda.NewFromConfig(c.cfg).ListTags(ctx, &lambda.ListTagsInput{
		Resource: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *lambda.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
