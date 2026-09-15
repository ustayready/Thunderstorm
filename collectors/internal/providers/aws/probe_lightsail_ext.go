package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
)

func init() {
	registerFetcher("GetContainerServiceDeployments", "aws:lightsail:container_service", fetchLightsailGetContainerServiceDeploymentsExt)
	registerFetcher("GetContainerServices", "aws:lightsail:container_service", fetchLightsailGetContainerServicesExt)
	registerFetcher("GetRelationalDatabaseMasterUserPassword", "aws:lightsail:relational_database", fetchLightsailGetRelationalDatabaseMasterUserPasswordExt)
}

// Exposure probe: aws-lightsail-container-environment-values and
// aws-lightsail-container-command-config
// (GetContainerServiceDeployments -> deployments[].containers.<name>.{environment,command}).
// native_id is the container service name.
func fetchLightsailGetContainerServiceDeploymentsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lightsail.NewFromConfig(c.cfg).GetContainerServiceDeployments(ctx, &lightsail.GetContainerServiceDeploymentsInput{
		ServiceName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *lightsail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-lightsail-container-service-tags-value-config
// (GetContainerServices -> containerServices[].tags[].value).
// native_id is the container service name; passing it scopes the call to one service.
func fetchLightsailGetContainerServicesExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lightsail.NewFromConfig(c.cfg).GetContainerServices(ctx, &lightsail.GetContainerServicesInput{
		ServiceName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *lightsail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-lightsail-database-master-password-output
// (GetRelationalDatabaseMasterUserPassword -> masterUserPassword).
// native_id is the relational database name.
func fetchLightsailGetRelationalDatabaseMasterUserPasswordExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lightsail.NewFromConfig(c.cfg).GetRelationalDatabaseMasterUserPassword(ctx, &lightsail.GetRelationalDatabaseMasterUserPasswordInput{
		RelationalDatabaseName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *lightsail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
