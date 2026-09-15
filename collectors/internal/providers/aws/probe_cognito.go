package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

func init() {
	registerFetcher("ListUsers", "aws:cognito:user_pool", fetchCognitoListUsers)
	registerFetcher("ListTagsForResource", "aws:cognito:user_pool", fetchCognitoListTagsForResource)
}

// Exposure probe: aws-cognito-user-attributes-data (ListUsers -> Users[].Attributes[].Value).
func fetchCognitoListUsers(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cognitoidentityprovider.NewFromConfig(c.cfg).ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cognitoidentityprovider.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-cognito-user-pool-tags-value-config (ListTagsForResource -> Tags.<value>).
func fetchCognitoListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cognitoidentityprovider.NewFromConfig(c.cfg).ListTagsForResource(ctx, &cognitoidentityprovider.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *cognitoidentityprovider.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
