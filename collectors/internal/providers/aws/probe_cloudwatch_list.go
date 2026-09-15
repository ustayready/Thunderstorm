package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

func init() {
	registerListFetcher("GetQueryResults", listFetchCloudwatchGetQueryResults)
	registerListFetcher("GetDashboard", listFetchCloudwatchGetDashboard)
	registerListFetcher("DescribeAlarms", listFetchCloudwatchDescribeAlarms)
	registerListFetcher("ListMetrics", listFetchCloudwatchListMetrics)
}

// listFetchCloudwatchGetQueryResults enumerates completed Logs Insights queries
// in the region and returns the results response for each query (read-only).
// The prober applies the site's response_path (results[][].{field,value}) to
// each item. Only Complete-status queries carry retrievable results.
func listFetchCloudwatchGetQueryResults(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := cloudwatchlogs.NewFromConfig(c.cfg)
	ro := func(o *cloudwatchlogs.Options) { o.Region = region }

	// Enumerate completed queries — only Complete queries have retrievable results.
	var queryIDs []string
	var nextToken *string
	for {
		listOut, err := svc.DescribeQueries(ctx, &cloudwatchlogs.DescribeQueriesInput{
			Status:    types.QueryStatusComplete,
			NextToken: nextToken,
		}, ro)
		if err != nil {
			return nil, err
		}
		for _, q := range listOut.Queries {
			if q.QueryId != nil {
				queryIDs = append(queryIDs, *q.QueryId)
			}
		}
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	var out []any
	for _, qid := range queryIDs {
		qid := qid
		d, err := svc.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
			QueryId: &qid,
		}, ro)
		if err != nil {
			continue // per-item error — skip
		}
		out = append(out, jsonify(d))
	}
	return out, nil
}

// listFetchCloudwatchGetDashboard enumerates all CloudWatch dashboards in the
// region and returns the full GetDashboard response for each (read-only).
// The prober applies the site's response_path (DashboardBody) to each item.
func listFetchCloudwatchGetDashboard(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := cloudwatch.NewFromConfig(c.cfg)
	ro := func(o *cloudwatch.Options) { o.Region = region }

	var out []any
	p := cloudwatch.NewListDashboardsPaginator(svc, &cloudwatch.ListDashboardsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, entry := range page.DashboardEntries {
			if entry.DashboardName == nil {
				continue
			}
			name := *entry.DashboardName
			d, err := svc.GetDashboard(ctx, &cloudwatch.GetDashboardInput{
				DashboardName: &name,
			}, ro)
			if err != nil {
				continue // per-item error — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchCloudwatchDescribeAlarms enumerates all CloudWatch alarms in the
// region and returns each page as a jsonified response (read-only). The prober
// applies the site's response_path
// (MetricAlarms[].AlarmDescription / CompositeAlarms[].AlarmDescription) to
// each item.
func listFetchCloudwatchDescribeAlarms(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := cloudwatch.NewFromConfig(c.cfg)
	ro := func(o *cloudwatch.Options) { o.Region = region }

	var out []any
	p := cloudwatch.NewDescribeAlarmsPaginator(svc, &cloudwatch.DescribeAlarmsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		out = append(out, jsonify(page))
	}
	return out, nil
}

// listFetchCloudwatchListMetrics enumerates all CloudWatch custom metric
// definitions in the region and returns each metric item as a jsonified
// response (read-only). The prober applies the site's response_path
// (Metrics[].Dimensions[].Value) to each item.
func listFetchCloudwatchListMetrics(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := cloudwatch.NewFromConfig(c.cfg)
	ro := func(o *cloudwatch.Options) { o.Region = region }

	var out []any
	p := cloudwatch.NewListMetricsPaginator(svc, &cloudwatch.ListMetricsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, m := range page.Metrics {
			out = append(out, jsonify(m))
		}
	}
	return out, nil
}
