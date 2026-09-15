package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

func init() {
	registerFetcher("GetCertificateAuthorityCsr", "aws:acmpca:certificate-authority", fetchACMPCAGetCertificateAuthorityCsr)
	registerFetcher("ListTags", "aws:acmpca:certificate-authority", fetchACMPCAListTags)
}

// Exposure probe: aws-acmpca-certificate-authority-csr (GetCertificateAuthorityCsr -> Csr).
func fetchACMPCAGetCertificateAuthorityCsr(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := acmpca.NewFromConfig(c.cfg).GetCertificateAuthorityCsr(ctx, &acmpca.GetCertificateAuthorityCsrInput{
		CertificateAuthorityArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *acmpca.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-acmpca-ca-tags-value-config (ListTags -> Tags[].Value).
func fetchACMPCAListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := acmpca.NewFromConfig(c.cfg).ListTags(ctx, &acmpca.ListTagsInput{
		CertificateAuthorityArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *acmpca.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
