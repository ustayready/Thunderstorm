package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

func init() {
	registerFetcher("DescribeCertificate", "aws:acm:certificate", fetchAcmDescribeCertificate)
	registerFetcher("ListTagsForCertificate", "aws:acm:certificate", fetchAcmListTagsForCertificate)
}

// Exposure probe: aws-acm-certificate-subject-metadata (DescribeCertificate -> Certificate.{DomainName,Subject,SubjectAlternativeNames}).
func fetchAcmDescribeCertificate(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := acm.NewFromConfig(c.cfg).DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *acm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-acm-certificate-tags-value-config (ListTagsForCertificate -> Tags[].Value).
func fetchAcmListTagsForCertificate(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := acm.NewFromConfig(c.cfg).ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
		CertificateArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *acm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
