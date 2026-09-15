package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func init() { register("backup:ListBackupVaults", opBackupListBackupVaults) }

// opBackupListBackupVaults enumerates Backup vaults (read-only).
func opBackupListBackupVaults(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := backup.NewFromConfig(c.cfg)
	p := backup.NewListBackupVaultsPaginator(svc, &backup.ListBackupVaultsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *backup.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, v := range out.BackupVaultList {
			recs = append(recs, Record{
				"backup_vault_name": aws.ToString(v.BackupVaultName),
				"backup_vault_arn":  aws.ToString(v.BackupVaultArn),
			})
		}
	}
	return recs, nil
}
