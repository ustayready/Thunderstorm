package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
)

func init() {
	registerFetcher("DescribeService", "aws:apprunner:service", fetchAppRunnerDescribeService)
	registerFetcher("ListTagsForResource", "aws:apprunner:service", fetchAppRunnerListTagsForResource)
}

// Exposure probe: aws-apprunner-runtime-environment-variables-config + aws-apprunner-build-start-command-config
// (DescribeService -> Service.SourceConfiguration.*).
func fetchAppRunnerDescribeService(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := apprunner.NewFromConfig(c.cfg).DescribeService(ctx, &apprunner.DescribeServiceInput{
		ServiceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *apprunner.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-apprunner-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchAppRunnerListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := apprunner.NewFromConfig(c.cfg).ListTagsForResource(ctx, &apprunner.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *apprunner.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
