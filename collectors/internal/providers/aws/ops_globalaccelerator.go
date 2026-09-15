package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
)

func init() { register("globalaccelerator:ListAccelerators", opGlobalAcceleratorListAccelerators) }

// opGlobalAcceleratorListAccelerators enumerates Global Accelerator accelerators (read-only).
func opGlobalAcceleratorListAccelerators(ctx context.Context, c *Client, _ string, _ map[string]string) ([]Record, error) {
	svc := globalaccelerator.NewFromConfig(c.cfg)
	p := globalaccelerator.NewListAcceleratorsPaginator(svc, &globalaccelerator.ListAcceleratorsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range out.Accelerators {
			recs = append(recs, Record{
				"accelerator_arn": aws.ToString(a.AcceleratorArn),
			})
		}
	}
	return recs, nil
}
