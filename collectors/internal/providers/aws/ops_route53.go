package aws

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

func init() { register("route53:ListHostedZones", opRoute53ListHostedZones) }

// opRoute53ListHostedZones enumerates Route 53 hosted zones (read-only).
// Route 53 is a global service; the region parameter is unused.
// Hosted zones do not carry an ARN in the API response, so only the id is set.
// The raw Id has the form /hostedzone/Z1234EXAMPLE; we strip the prefix.
func opRoute53ListHostedZones(ctx context.Context, c *Client, _ string, _ map[string]string) ([]Record, error) {
	svc := route53.NewFromConfig(c.cfg)
	p := route53.NewListHostedZonesPaginator(svc, &route53.ListHostedZonesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, z := range out.HostedZones {
			id := strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/")
			recs = append(recs, Record{
				"hosted_zone_id": id,
			})
		}
	}
	return recs, nil
}
