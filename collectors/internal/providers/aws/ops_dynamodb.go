package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func init() { register("dynamodb:ListTables", opDynamoDBListTables) }

// opDynamoDBListTables enumerates DynamoDB tables (read-only).
func opDynamoDBListTables(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := dynamodb.NewFromConfig(c.cfg)
	p := dynamodb.NewListTablesPaginator(svc, &dynamodb.ListTablesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *dynamodb.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, name := range out.TableNames {
			recs = append(recs, Record{"table_name": name})
		}
	}
	return recs, nil
}
