package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func init() {
	registerFetcher("GetDistributionConfig", "aws:cloudfront:distribution", fetchCloudfrontGetDistributionConfig)
	registerFetcher("ListTagsForResource", "aws:cloudfront:distribution", fetchCloudfrontListTagsForResource)
}

// Exposure probe: aws-cloudfront-origin-custom-header-value (GetDistributionConfig -> DistributionConfig.Origins.Items[].CustomHeaders.Items[].HeaderValue).
func fetchCloudfrontGetDistributionConfig(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudfront.NewFromConfig(c.cfg).GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{
		Id: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cloudfront.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-cloudfront-resource-tags-value-config (ListTagsForResource -> Tags.Items[].Value).
func fetchCloudfrontListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudfront.NewFromConfig(c.cfg).ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{
		Resource: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *cloudfront.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
