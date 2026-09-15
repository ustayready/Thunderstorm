package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func init() {
	registerFetcher("DescribeKey", "aws:kms:key", fetchKmsDescribeKey)
	registerFetcher("ListResourceTags", "aws:kms:key", fetchKmsListResourceTags)
}

// Exposure probe: aws-kms-key-description-config (DescribeKey -> KeyMetadata.Description).
func fetchKmsDescribeKey(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := kms.NewFromConfig(c.cfg).DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *kms.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-kms-key-tags-value-config (ListResourceTags -> Tags[].TagValue).
func fetchKmsListResourceTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := kms.NewFromConfig(c.cfg).ListResourceTags(ctx, &kms.ListResourceTagsInput{
		KeyId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *kms.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
