package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func init() { registerFactCollector("backup-resource-policy", "regional", collectBackupPolicies) }

// collectBackupPolicies emits Backup vault access policies as resource_policy facts
// (CrossAccountTrust surface). Each vault is checked for a resource-based access
// policy via GetBackupVaultAccessPolicy. Vaults with no policy are silently skipped.
func collectBackupPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := backup.NewFromConfig(c.cfg)
	ro := func(o *backup.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := backup.NewListBackupVaultsPaginator(svc, &backup.ListBackupVaultsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, v := range out.BackupVaultList {
			name := aws.ToString(v.BackupVaultName)
			if name == "" {
				continue
			}
			pol, e := svc.GetBackupVaultAccessPolicy(ctx, &backup.GetBackupVaultAccessPolicyInput{
				BackupVaultName: aws.String(name),
			}, ro)
			if e != nil || pol.Policy == nil {
				continue // no policy on this vault
			}
			arn := firstNonEmpty(aws.ToString(v.BackupVaultArn), name)
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				arn, "", map[string]any{"policy": aws.ToString(pol.Policy)})
		}
	}
	return s.n - start, nil
}
