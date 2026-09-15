package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
)

func init() {
	registerFetcher("GetApp", "aws:amplify:app", fetchAmplifyGetApp)
}

// Exposure probe: aws-amplify-app-environment-variables, aws-amplify-app-build-spec,
// aws-amplify-app-tags-value-config (GetApp -> app.environmentVariables, app.buildSpec, app.tags).
func fetchAmplifyGetApp(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := amplify.NewFromConfig(c.cfg).GetApp(ctx, &amplify.GetAppInput{
		AppId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *amplify.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
