package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
)

func init() { register("timestream:ListDatabases", opTimestreamListDatabases) }

// opTimestreamListDatabases enumerates Timestream databases (read-only).
func opTimestreamListDatabases(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := timestreamwrite.NewFromConfig(c.cfg)
	p := timestreamwrite.NewListDatabasesPaginator(svc, &timestreamwrite.ListDatabasesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *timestreamwrite.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Databases {
			recs = append(recs, Record{
				"database_name": aws.ToString(item.DatabaseName),
				"arn":           aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
