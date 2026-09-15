package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

func init() { register("cognito:ListUserPools", opCognitoListUserPools) }

// opCognitoListUserPools enumerates Cognito User Pools (read-only).
func opCognitoListUserPools(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := cognitoidentityprovider.NewFromConfig(c.cfg)
	p := cognitoidentityprovider.NewListUserPoolsPaginator(svc, &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int32(60),
	})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *cognitoidentityprovider.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, pool := range out.UserPools {
			recs = append(recs, Record{
				"user_pool_id": aws.ToString(pool.Id),
			})
		}
	}
	return recs, nil
}
