package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func init() { register("guardduty:ListDetectors", opGuardDutyListDetectors) }

// opGuardDutyListDetectors enumerates GuardDuty detectors (read-only).
func opGuardDutyListDetectors(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := guardduty.NewFromConfig(c.cfg)
	p := guardduty.NewListDetectorsPaginator(svc, &guardduty.ListDetectorsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *guardduty.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, id := range out.DetectorIds {
			recs = append(recs, Record{
				"detector_id": id,
			})
		}
	}
	return recs, nil
}
