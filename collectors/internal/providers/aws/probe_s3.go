package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	registerFetcher("GetBucketPolicy", "aws:s3:bucket", fetchS3GetBucketPolicy)
	registerFetcher("GetBucketTagging", "aws:s3:bucket", fetchS3GetBucketTagging)
	registerFetcher("GetBucketWebsite", "aws:s3:bucket", fetchS3GetBucketWebsite)
}

// Exposure probe: aws-s3-bucket-policy-document-config (GetBucketPolicy -> Policy).
func fetchS3GetBucketPolicy(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := s3.NewFromConfig(c.cfg).GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *s3.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-s3-bucket-tags-value-config (GetBucketTagging -> TagSet[].Value).
func fetchS3GetBucketTagging(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := s3.NewFromConfig(c.cfg).GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *s3.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-s3-website-routing-rule-config (GetBucketWebsite -> RoutingRules[].Redirect).
func fetchS3GetBucketWebsite(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := s3.NewFromConfig(c.cfg).GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
		Bucket: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *s3.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
