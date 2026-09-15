package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

func init() { register("cloudtrail:DescribeTrails", opCloudTrailDescribeTrails) }

// opCloudTrailDescribeTrails enumerates CloudTrail trails (read-only).
func opCloudTrailDescribeTrails(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := cloudtrail.NewFromConfig(c.cfg)
	out, err := svc.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{}, func(o *cloudtrail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, t := range out.TrailList {
		recs = append(recs, Record{
			"trail_name": aws.ToString(t.Name),
			"trail_arn":  aws.ToString(t.TrailARN),
		})
	}
	return recs, nil
}
