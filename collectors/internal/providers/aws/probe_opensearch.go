package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

func init() {
	registerFetcher("DescribeDomainConfig", "aws:opensearch:domain", fetchOpensearchDescribeDomainConfig)
	registerFetcher("ListTags", "aws:opensearch:domain", fetchOpensearchListTags)
}

// Exposure probe: aws-opensearch-saml-idp-metadata (DescribeDomainConfig -> DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp.MetadataContent).
func fetchOpensearchDescribeDomainConfig(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opensearch.NewFromConfig(c.cfg).DescribeDomainConfig(ctx, &opensearch.DescribeDomainConfigInput{
		DomainName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *opensearch.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-opensearch-resource-tags-value-config (ListTags -> TagList[].Value).
func fetchOpensearchListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := opensearch.NewFromConfig(c.cfg).ListTags(ctx, &opensearch.ListTagsInput{
		ARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *opensearch.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
