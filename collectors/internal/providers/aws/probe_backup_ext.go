package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func init() {
	registerFetcher("GetRecoveryPointRestoreMetadata", "aws:backup:vault", fetchBackupGetRecoveryPointRestoreMetadataExt)
}

// Exposure probe: aws-backup-restore-metadata-config
// (GetRecoveryPointRestoreMetadata -> RestoreMetadata.<value>).
//
// A single vault item maps to many recovery points; we enumerate them with
// ListRecoveryPointsByBackupVault and then call GetRecoveryPointRestoreMetadata
// for each one, accumulating results under the recovery-point ARN key so the
// prober's response-path walker can inspect every RestoreMetadata map.
func fetchBackupGetRecoveryPointRestoreMetadataExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	vaultName := itemStr(item, "native_id", "arn")
	if vaultName == "" {
		return jsonify(map[string]any{"RecoveryPoints": nil}), nil
	}

	svc := backup.NewFromConfig(c.cfg)
	opt := func(o *backup.Options) { o.Region = region }

	// Enumerate all recovery points in this vault.
	var recoveryPointARNs []string
	var nextToken *string
	for {
		out, err := svc.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{
			BackupVaultName: aws.String(vaultName),
			NextToken:       nextToken,
		}, opt)
		if err != nil {
			return nil, err
		}
		for _, rp := range out.RecoveryPoints {
			if rp.RecoveryPointArn != nil {
				recoveryPointARNs = append(recoveryPointARNs, *rp.RecoveryPointArn)
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	// For each recovery point, fetch the restore metadata and accumulate results.
	results := make([]any, 0, len(recoveryPointARNs))
	for _, rpARN := range recoveryPointARNs {
		meta, err := svc.GetRecoveryPointRestoreMetadata(ctx, &backup.GetRecoveryPointRestoreMetadataInput{
			BackupVaultName:  aws.String(vaultName),
			RecoveryPointArn: aws.String(rpARN),
		}, opt)
		if err != nil {
			// A single unavailable recovery point should not abort the whole vault;
			// the prober handles per-item errors, so we skip and continue.
			continue
		}
		results = append(results, meta)
	}

	return jsonify(map[string]any{"RecoveryPoints": results}), nil
}
