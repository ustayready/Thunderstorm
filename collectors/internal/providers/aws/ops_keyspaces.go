package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
)

func init() { register("cassandra:Select", opKeyspacesListKeyspaces) }

// opKeyspacesListKeyspaces enumerates Keyspaces keyspaces (read-only).
func opKeyspacesListKeyspaces(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := keyspaces.NewFromConfig(c.cfg)
	p := keyspaces.NewListKeyspacesPaginator(svc, &keyspaces.ListKeyspacesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *keyspaces.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, ks := range out.Keyspaces {
			recs = append(recs, Record{
				"keyspace_name": aws.ToString(ks.KeyspaceName),
				"arn":           aws.ToString(ks.ResourceArn),
			})
		}
	}
	return recs, nil
}
