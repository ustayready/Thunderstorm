package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

func init() { register("es:ListDomainNames", opOpenSearchListDomainNames) }

// opOpenSearchListDomainNames enumerates OpenSearch domains (read-only).
func opOpenSearchListDomainNames(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := opensearch.NewFromConfig(c.cfg)
	out, err := svc.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{}, func(o *opensearch.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, d := range out.DomainNames {
		recs = append(recs, Record{
			"domain_name": aws.ToString(d.DomainName),
		})
	}
	return recs, nil
}
