package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/ram/types"
)

func init() { register("ram:GetResourceShares", opRAMGetResourceShares) }

// opRAMGetResourceShares enumerates RAM resource shares owned by this account (read-only).
func opRAMGetResourceShares(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ram.NewFromConfig(c.cfg)
	p := ram.NewGetResourceSharesPaginator(svc, &ram.GetResourceSharesInput{
		ResourceOwner: types.ResourceOwnerSelf,
	})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ram.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.ResourceShares {
			recs = append(recs, Record{
				"resource_share_arn": aws.ToString(item.ResourceShareArn),
			})
		}
	}
	return recs, nil
}
