package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func init() {
	registerFactCollector("secretsmanager-resource-policy", "regional", collectSecretsmanagerPolicies)
}

// collectSecretsmanagerPolicies emits Secrets Manager resource-based policies as
// resource_policy facts (CrossAccountTrust surface). It pages through all secrets
// in the region via ListSecrets, then fetches each secret's resource policy via
// GetResourcePolicy. Secrets with no resource policy attached are silently skipped.
func collectSecretsmanagerPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := secretsmanager.NewFromConfig(c.cfg)
	ro := func(o *secretsmanager.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := secretsmanager.NewListSecretsPaginator(svc, &secretsmanager.ListSecretsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, secret := range out.SecretList {
			arn := aws.ToString(secret.ARN)
			if arn == "" {
				continue
			}
			pol, e := svc.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
				SecretId: aws.String(arn),
			}, ro)
			if e != nil || pol.ResourcePolicy == nil {
				continue // no policy attached to this secret
			}
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				arn, "", map[string]any{"policy": aws.ToString(pol.ResourcePolicy)})
		}
	}
	return s.n - start, nil
}
