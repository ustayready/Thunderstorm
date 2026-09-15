package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func init() {
	registerFetcher("FilterLogEvents", "aws:cloudwatch:log_group", fetchCloudWatchLogsFilterLogEvents)
	registerFetcher("DescribeQueries", "aws:cloudwatch:log_group", fetchCloudWatchLogsDescribeQueries)
	registerFetcher("ListTagsForResource", "aws:cloudwatch:log_group", fetchCloudWatchLogsListTagsForResource)
}

// Exposure probe: aws-cloudwatch-log-event-message (FilterLogEvents -> events[].message).
func fetchCloudWatchLogsFilterLogEvents(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudwatchlogs.NewFromConfig(c.cfg).FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cloudwatchlogs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-cloudwatch-logs-insights-query-string (DescribeQueries -> queries[].queryString).
func fetchCloudWatchLogsDescribeQueries(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudwatchlogs.NewFromConfig(c.cfg).DescribeQueries(ctx, &cloudwatchlogs.DescribeQueriesInput{
		LogGroupName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *cloudwatchlogs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-cloudwatch-log-group-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchCloudWatchLogsListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudwatchlogs.NewFromConfig(c.cfg).ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *cloudwatchlogs.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
