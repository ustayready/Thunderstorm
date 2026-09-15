package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() {
	registerListFetcher("DownloadDBLogFilePortion", listFetchRdsDownloadDBLogFilePortion)
	registerListFetcher("DescribeDBParameters", listFetchRdsDescribeDBParameters)
}

// listFetchRdsDownloadDBLogFilePortion enumerates every DB instance in the
// region, lists each instance's log files, and downloads the first portion of
// each log (read-only). The prober applies the site's response_path
// (LogFileData) to each item.
func listFetchRdsDownloadDBLogFilePortion(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := rds.NewFromConfig(c.cfg)
	ro := func(o *rds.Options) { o.Region = region }
	var out []any

	instP := rds.NewDescribeDBInstancesPaginator(svc, &rds.DescribeDBInstancesInput{})
	for instP.HasMorePages() {
		instPage, err := instP.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, inst := range instPage.DBInstances {
			if inst.DBInstanceIdentifier == nil {
				continue
			}
			dbID := inst.DBInstanceIdentifier

			logP := rds.NewDescribeDBLogFilesPaginator(svc, &rds.DescribeDBLogFilesInput{
				DBInstanceIdentifier: dbID,
			})
			for logP.HasMorePages() {
				logPage, err := logP.NextPage(ctx, ro)
				if err != nil {
					break // per-instance error — skip remaining logs for this instance
				}
				for _, logFile := range logPage.DescribeDBLogFiles {
					if logFile.LogFileName == nil {
						continue
					}
					d, e := svc.DownloadDBLogFilePortion(ctx, &rds.DownloadDBLogFilePortionInput{
						DBInstanceIdentifier: dbID,
						LogFileName:          logFile.LogFileName,
					}, ro)
					if e != nil {
						continue // per-item error (not found / access) — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}

// listFetchRdsDescribeDBParameters enumerates all DB parameter groups in the
// region and returns the full parameter list for each (read-only). The prober
// applies the site's response_path (Parameters[].ParameterValue) to each item.
func listFetchRdsDescribeDBParameters(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := rds.NewFromConfig(c.cfg)
	ro := func(o *rds.Options) { o.Region = region }
	var out []any

	grpP := rds.NewDescribeDBParameterGroupsPaginator(svc, &rds.DescribeDBParameterGroupsInput{})
	for grpP.HasMorePages() {
		grpPage, err := grpP.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, grp := range grpPage.DBParameterGroups {
			if grp.DBParameterGroupName == nil {
				continue
			}
			paramP := rds.NewDescribeDBParametersPaginator(svc, &rds.DescribeDBParametersInput{
				DBParameterGroupName: grp.DBParameterGroupName,
			})
			for paramP.HasMorePages() {
				paramPage, err := paramP.NextPage(ctx, ro)
				if err != nil {
					break // per-group error — skip remaining pages for this group
				}
				out = append(out, jsonify(paramPage))
			}
		}
	}
	return out, nil
}
