package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

func init() {
	registerFetcher("DescribeConfigRules", "aws:config:config-rule", fetchConfigDescribeConfigRules)
	registerFetcher("DescribeRemediationConfigurations", "aws:config:config-rule", fetchConfigDescribeRemediationConfigurations)
	registerFetcher("ListTagsForResource", "aws:config:config-rule", fetchConfigListTagsForResource)
}

// Exposure probe: aws-config-rule-input-parameters (DescribeConfigRules -> ConfigRules[].InputParameters).
func fetchConfigDescribeConfigRules(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := configservice.NewFromConfig(c.cfg).DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{
		ConfigRuleNames: []string{itemStr(item, "native_id", "arn")},
	}, func(o *configservice.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-config-remediation-static-values (DescribeRemediationConfigurations -> RemediationConfigurations[].Parameters.<name>.StaticValue.Values[]).
func fetchConfigDescribeRemediationConfigurations(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := configservice.NewFromConfig(c.cfg).DescribeRemediationConfigurations(ctx, &configservice.DescribeRemediationConfigurationsInput{
		ConfigRuleNames: []string{itemStr(item, "native_id", "arn")},
	}, func(o *configservice.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-config-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchConfigListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := configservice.NewFromConfig(c.cfg).ListTagsForResource(ctx, &configservice.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *configservice.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
