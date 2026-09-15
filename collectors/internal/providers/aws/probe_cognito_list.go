package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

func init() {
	registerListFetcher("DescribeUserPoolClient", listFetchCognitoDescribeUserPoolClient)
}

// listFetchCognitoDescribeUserPoolClient enumerates all user pools in the
// region, then all app clients per pool, and fetches full detail for each via
// DescribeUserPoolClient (read-only); per-item errors are skipped.
func listFetchCognitoDescribeUserPoolClient(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := cognitoidentityprovider.NewFromConfig(c.cfg)
	ro := func(o *cognitoidentityprovider.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate user pools.
	pp := cognitoidentityprovider.NewListUserPoolsPaginator(svc, &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int32(60),
	})
	for pp.HasMorePages() {
		poolPage, err := pp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, pool := range poolPage.UserPools {
			if pool.Id == nil {
				continue
			}
			poolID := pool.Id

			// Step 2: enumerate app clients for this user pool.
			cp := cognitoidentityprovider.NewListUserPoolClientsPaginator(svc, &cognitoidentityprovider.ListUserPoolClientsInput{
				UserPoolId: poolID,
			})
			for cp.HasMorePages() {
				clientPage, err := cp.NextPage(ctx, ro)
				if err != nil {
					break // move to next pool on error
				}
				for _, client := range clientPage.UserPoolClients {
					if client.ClientId == nil {
						continue
					}
					// Step 3: fetch full app-client detail (includes ClientSecret).
					d, e := svc.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
						UserPoolId: poolID,
						ClientId:   client.ClientId,
					}, ro)
					if e != nil {
						continue // per-item error — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}
