package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
)

func init() {
	registerFetcher("GetWebACL", "aws:waf:web_acl", fetchWafGetWebACL)
	registerFetcher("ListTagsForResource", "aws:waf:web_acl", fetchWafListTagsForResource)
}

// Exposure probe: aws-waf-byte-match-search-string / aws-waf-custom-response-body-content /
// aws-waf-inserted-header-values (GetWebACL -> WebACL.*).
func fetchWafGetWebACL(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := wafv2.NewFromConfig(c.cfg).GetWebACL(ctx, &wafv2.GetWebACLInput{
		ARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *wafv2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-waf-resource-tags-value-config (ListTagsForResource -> TagInfoForResource.TagList[].Value).
func fetchWafListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := wafv2.NewFromConfig(c.cfg).ListTagsForResource(ctx, &wafv2.ListTagsForResourceInput{
		ResourceARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *wafv2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
