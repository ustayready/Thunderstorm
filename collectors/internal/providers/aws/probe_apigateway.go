package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func init() {
	registerFetcher("GetTags", "aws:apigateway:rest-api", fetchAPIGatewayGetTags)
}

// Exposure probe: aws-apigateway-resource-tags-value-config (GetTags -> tags.<value>).
func fetchAPIGatewayGetTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := apigateway.NewFromConfig(c.cfg).GetTags(ctx, &apigateway.GetTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *apigateway.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
