package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func init() { register("cloudwatch:DescribeLogGroups", opCloudWatchDescribeLogGroups) }

// opCloudWatchDescribeLogGroups enumerates CloudWatch Logs log groups (read-only).
func opCloudWatchDescribeLogGroups(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := cloudwatchlogs.NewFromConfig(c.cfg)
	p := cloudwatchlogs.NewDescribeLogGroupsPaginator(svc, &cloudwatchlogs.DescribeLogGroupsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *cloudwatchlogs.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, lg := range out.LogGroups {
			recs = append(recs, Record{
				"log_group_name": aws.ToString(lg.LogGroupName),
				"arn":            aws.ToString(lg.Arn),
			})
		}
	}
	return recs, nil
}
