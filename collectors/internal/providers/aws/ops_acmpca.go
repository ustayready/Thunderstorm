package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

func init() { register("acm-pca:ListCertificateAuthorities", opACMPCAListCertificateAuthorities) }

// opACMPCAListCertificateAuthorities enumerates ACM Private CA certificate authorities (read-only).
func opACMPCAListCertificateAuthorities(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := acmpca.NewFromConfig(c.cfg)
	p := acmpca.NewListCertificateAuthoritiesPaginator(svc, &acmpca.ListCertificateAuthoritiesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *acmpca.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.CertificateAuthorities {
			recs = append(recs, Record{
				"arn": aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
