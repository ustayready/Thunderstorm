package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func init() {
	registerFetcher("Scan", "aws:dynamodb:table", fetchDynamoDBScan)
	registerFetcher("GetResourcePolicy", "aws:dynamodb:table", fetchDynamoDBGetResourcePolicy)
	registerFetcher("ListTagsOfResource", "aws:dynamodb:table", fetchDynamoDBListTagsOfResource)
}

// Exposure probe: aws-dynamodb-item-attribute-data (Scan -> Items[].<attribute-name>).
func fetchDynamoDBScan(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := dynamodb.NewFromConfig(c.cfg).Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *dynamodb.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-dynamodb-table-resource-policy-config (GetResourcePolicy -> Policy).
func fetchDynamoDBGetResourcePolicy(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := dynamodb.NewFromConfig(c.cfg).GetResourcePolicy(ctx, &dynamodb.GetResourcePolicyInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *dynamodb.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-dynamodb-table-tags-value-config (ListTagsOfResource -> Tags[].Value).
func fetchDynamoDBListTagsOfResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := dynamodb.NewFromConfig(c.cfg).ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *dynamodb.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
