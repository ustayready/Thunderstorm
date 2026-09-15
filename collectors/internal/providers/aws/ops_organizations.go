package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

func init() { register("organizations:ListAccounts", opOrganizationsListAccounts) }

// opOrganizationsListAccounts enumerates Organizations member accounts (read-only).
func opOrganizationsListAccounts(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := organizations.NewFromConfig(c.cfg)
	p := organizations.NewListAccountsPaginator(svc, &organizations.ListAccountsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *organizations.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Accounts {
			recs = append(recs, Record{
				"account_id": aws.ToString(item.Id),
				"arn":        aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
