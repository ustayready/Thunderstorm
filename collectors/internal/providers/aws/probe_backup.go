package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func init() {
	registerFetcher("GetBackupVaultAccessPolicy", "aws:backup:vault", fetchBackupGetBackupVaultAccessPolicy)
	registerFetcher("ListTags", "aws:backup:vault", fetchBackupListTags)
}

// Exposure probe: aws-backup-vault-access-policy-config (GetBackupVaultAccessPolicy -> Policy).
func fetchBackupGetBackupVaultAccessPolicy(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := backup.NewFromConfig(c.cfg).GetBackupVaultAccessPolicy(ctx, &backup.GetBackupVaultAccessPolicyInput{
		BackupVaultName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *backup.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-backup-resource-tags-value-config (ListTags -> Tags.<value>).
func fetchBackupListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := backup.NewFromConfig(c.cfg).ListTags(ctx, &backup.ListTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *backup.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
