package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func init() { register("kms:ListKeys", opKMSListKeys) }

// opKMSListKeys enumerates KMS keys (read-only), capturing the alias, key manager
// (AWS vs CUSTOMER), and description so the graph shows something human-readable
// (e.g. "aws/secretsmanager") instead of an opaque key GUID.
func opKMSListKeys(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := kms.NewFromConfig(c.cfg)
	ro := func(o *kms.Options) { o.Region = region }

	// alias map: target key id -> alias name
	aliasOf := map[string]string{}
	ap := kms.NewListAliasesPaginator(svc, &kms.ListAliasesInput{})
	for ap.HasMorePages() {
		out, err := ap.NextPage(ctx, ro)
		if err != nil {
			break
		}
		for _, a := range out.Aliases {
			if a.TargetKeyId != nil {
				aliasOf[aws.ToString(a.TargetKeyId)] = aws.ToString(a.AliasName)
			}
		}
	}

	p := kms.NewListKeysPaginator(svc, &kms.ListKeysInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return nil, err
		}
		for _, k := range out.Keys {
			kid := aws.ToString(k.KeyId)
			rec := Record{"key_id": kid, "key_arn": aws.ToString(k.KeyArn)}
			if al, ok := aliasOf[kid]; ok {
				rec["alias"] = al
			}
			if dk, e := svc.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId}, ro); e == nil && dk.KeyMetadata != nil {
				rec["key_manager"] = string(dk.KeyMetadata.KeyManager)
				rec["description"] = aws.ToString(dk.KeyMetadata.Description)
			}
			recs = append(recs, rec)
		}
	}
	return recs, nil
}
