package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/qldb"
)

func init() { register("qldb:ListLedgers", opQLDBListLedgers) }

// opQLDBListLedgers enumerates QLDB ledgers (read-only).
func opQLDBListLedgers(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := qldb.NewFromConfig(c.cfg)
	p := qldb.NewListLedgersPaginator(svc, &qldb.ListLedgersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *qldb.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Ledgers {
			recs = append(recs, Record{
				"ledger_name": aws.ToString(item.Name),
			})
		}
	}
	return recs, nil
}
