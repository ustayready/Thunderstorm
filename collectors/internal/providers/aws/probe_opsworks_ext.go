package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opsworks"
)

func init() {
	// All three DescribeApps exposure sites share the same operation and are
	// driven by the stack's native_id via the StackId filter.
	registerFetcher("DescribeApps", "aws:opsworks:stack", fetchOpsworksDescribeAppsExt)

	// Deployment command args site — enumerate all deployments for a stack.
	registerFetcher("DescribeDeployments", "aws:opsworks:stack", fetchOpsworksDescribeDeploymentsExt)
}

// Exposure probe: aws-opsworks-app-environment-value, aws-opsworks-app-source-credentials,
// aws-opsworks-app-ssl-private-key (DescribeApps -> Apps[].Environment[].Value /
// Apps[].AppSource.{Password,SshKey} / Apps[].SslConfiguration.PrivateKey).
// The stack's native_id is passed as StackId to enumerate all apps in the stack.
func fetchOpsworksDescribeAppsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opsworks.NewFromConfig(c.cfg).DescribeApps(ctx, &opsworks.DescribeAppsInput{
		StackId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *opsworks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-opsworks-deployment-command-args
// (DescribeDeployments -> Deployments[].Command.Args.<value>).
// The stack's native_id is passed as StackId to enumerate all deployments for the stack.
func fetchOpsworksDescribeDeploymentsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opsworks.NewFromConfig(c.cfg).DescribeDeployments(ctx, &opsworks.DescribeDeploymentsInput{
		StackId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *opsworks.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
