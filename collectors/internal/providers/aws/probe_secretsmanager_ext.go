package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func init() {
	registerFetcher("BatchGetSecretValue", "aws:secretsmanager:secret", fetchSecretsmanagerBatchGetSecretValueExt)
	registerFetcher("GetResourcePolicy", "aws:secretsmanager:secret", fetchSecretsmanagerGetResourcePolicyExt)
	registerFetcher("DescribeSecret", "aws:secretsmanager:secret", fetchSecretsmanagerDescribeSecretExt)
}

// fetchSecretsmanagerBatchGetSecretValueExt implements the exposure probe for
// aws-secretsmanager-secret-value-batch (BatchGetSecretValue ->
// SecretValues[].SecretString / SecretValues[].SecretBinary).
// We pass the single secret ARN/name as a one-element SecretIdList so the
// response shape matches the catalog's response_path.
func fetchSecretsmanagerBatchGetSecretValueExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	id := itemStr(item, "arn", "native_id")
	out, err := secretsmanager.NewFromConfig(c.cfg).BatchGetSecretValue(ctx,
		&secretsmanager.BatchGetSecretValueInput{
			SecretIdList: []string{id},
		},
		func(o *secretsmanager.Options) { o.Region = region },
	)
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSecretsmanagerGetResourcePolicyExt implements the exposure probe for
// aws-secretsmanager-resource-policy-config (GetResourcePolicy ->
// ResourcePolicy).
func fetchSecretsmanagerGetResourcePolicyExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := secretsmanager.NewFromConfig(c.cfg).GetResourcePolicy(ctx,
		&secretsmanager.GetResourcePolicyInput{
			SecretId: aws.String(itemStr(item, "arn", "native_id")),
		},
		func(o *secretsmanager.Options) { o.Region = region },
	)
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchSecretsmanagerDescribeSecretExt implements the exposure probes for
// aws-secretsmanager-secret-description-config and
// aws-secretsmanager-secret-tags-value-config (DescribeSecret ->
// Description / Tags[].Value).
func fetchSecretsmanagerDescribeSecretExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := secretsmanager.NewFromConfig(c.cfg).DescribeSecret(ctx,
		&secretsmanager.DescribeSecretInput{
			SecretId: aws.String(itemStr(item, "arn", "native_id")),
		},
		func(o *secretsmanager.Options) { o.Region = region },
	)
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
