package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

func init() { registerFactCollector("acmpca-resource-policy", "regional", collectAcmpcaPolicies) }

// collectAcmpcaPolicies emits ACM Private CA resource-based policies as
// resource_policy facts (CrossAccountTrust surface). Each CA is listed per
// region; CAs with no resource policy attached are silently skipped.
func collectAcmpcaPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := acmpca.NewFromConfig(c.cfg)
	ro := func(o *acmpca.Options) { o.Region = region }
	start := s.n

	p := acmpca.NewListCertificateAuthoritiesPaginator(svc, &acmpca.ListCertificateAuthoritiesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, ca := range out.CertificateAuthorities {
			arn := aws.ToString(ca.Arn)
			if arn == "" {
				continue
			}
			pol, e := svc.GetPolicy(ctx, &acmpca.GetPolicyInput{ResourceArn: aws.String(arn)}, ro)
			if e != nil || pol.Policy == nil {
				continue // no policy attached, or CA deleted mid-scan
			}
			s.emitFact("resource_policy", "CrossAccountTrust", s.scopeRegion(region),
				arn, "", map[string]any{"policy": aws.ToString(pol.Policy)})
		}
	}
	return s.n - start, nil
}
