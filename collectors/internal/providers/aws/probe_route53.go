package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

func init() {
	registerFetcher("ListResourceRecordSets", "aws:route53:hosted_zone", fetchRoute53ListResourceRecordSets)
}

// Exposure probe: aws-route53-resource-record-values (ListResourceRecordSets -> ResourceRecordSets[].ResourceRecords[].Value).
func fetchRoute53ListResourceRecordSets(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
