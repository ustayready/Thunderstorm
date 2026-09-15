package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

func init() { register("acm:ListCertificates", opACMListCertificates) }

// opACMListCertificates enumerates ACM certificates (read-only).
func opACMListCertificates(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := acm.NewFromConfig(c.cfg)
	p := acm.NewListCertificatesPaginator(svc, &acm.ListCertificatesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *acm.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.CertificateSummaryList {
			recs = append(recs, Record{
				"certificate_arn": aws.ToString(item.CertificateArn),
			})
		}
	}
	return recs, nil
}
