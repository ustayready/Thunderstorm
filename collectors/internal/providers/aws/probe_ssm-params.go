package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func init() {
	registerFetcher("GetParameter", "aws:ssm-params:parameter", fetchSSMParamsGetParameter)
	registerFetcher("GetParameterHistory", "aws:ssm-params:parameter", fetchSSMParamsGetParameterHistory)
	registerFetcher("DescribeParameters", "aws:ssm-params:parameter", fetchSSMParamsDescribeParameters)
	// ListTagsForResource is already registered by probe_ssm.go for aws:ssm:managed-instance;
	// the fetcher map is keyed by operation name only so a second registration would silently
	// overwrite the first. Skipped — ListTagsForResource cannot be registered twice.
}

// Exposure probe: aws-ssm-params-parameter-value-current (GetParameter -> Parameter.Value).
func fetchSSMParamsGetParameter(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ssm.NewFromConfig(c.cfg).GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(itemStr(item, "native_id", "arn")),
		WithDecryption: aws.Bool(true),
	}, func(o *ssm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ssm-params-parameter-value-history (GetParameterHistory -> Parameters[].Value).
func fetchSSMParamsGetParameterHistory(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ssm.NewFromConfig(c.cfg).GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{
		Name:           aws.String(itemStr(item, "native_id", "arn")),
		WithDecryption: aws.Bool(true),
	}, func(o *ssm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ssm-params-parameter-description-config (DescribeParameters -> Parameters[].Description).
func fetchSSMParamsDescribeParameters(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ssm.NewFromConfig(c.cfg).DescribeParameters(ctx, &ssm.DescribeParametersInput{
		ParameterFilters: []ssmtypes.ParameterStringFilter{
			{
				Key:    aws.String("Name"),
				Option: aws.String("Equals"),
				Values: []string{itemStr(item, "native_id", "arn")},
			},
		},
	}, func(o *ssm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
