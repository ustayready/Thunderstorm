package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
)

func init() { register("vpc-lattice:ListServiceNetworks", opVPCLatticeListServiceNetworks) }

// opVPCLatticeListServiceNetworks enumerates VPC Lattice service networks (read-only).
func opVPCLatticeListServiceNetworks(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := vpclattice.NewFromConfig(c.cfg)
	p := vpclattice.NewListServiceNetworksPaginator(svc, &vpclattice.ListServiceNetworksInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *vpclattice.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Items {
			recs = append(recs, Record{
				"id":  aws.ToString(item.Id),
				"arn": aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
