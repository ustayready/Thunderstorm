package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
)

func init() { register("controltower:ListLandingZones", opControlTowerListLandingZones) }

// opControlTowerListLandingZones enumerates Control Tower landing zones (read-only).
func opControlTowerListLandingZones(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := controltower.NewFromConfig(c.cfg)
	p := controltower.NewListLandingZonesPaginator(svc, &controltower.ListLandingZonesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *controltower.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, lz := range out.LandingZones {
			recs = append(recs, Record{
				"arn": aws.ToString(lz.Arn),
			})
		}
	}
	return recs, nil
}
