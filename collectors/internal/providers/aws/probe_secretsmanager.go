package aws

import "context"

// Exposure probe: aws-secretsmanager-secret-value-current (GetSecretValue).
func init() {
	registerFetcher("GetSecretValue", "aws:secretsmanager:secret", fetchGetSecretValue)
}

func fetchGetSecretValue(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	v, err := c.GetSecretValue(ctx, region, itemStr(item, "arn", "native_id"))
	if err != nil {
		return nil, err
	}
	// Shape it so the catalog path "SecretString / SecretBinary" resolves.
	return map[string]any{"SecretString": v}, nil
}
