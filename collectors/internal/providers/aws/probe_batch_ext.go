package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/batch/types"
)

func init() {
	registerFetcher("DescribeJobDefinitions", "aws:batch:job-queue", fetchBatchDescribeJobDefinitionsExt)
	registerFetcher("DescribeJobs", "aws:batch:job-queue", fetchBatchDescribeJobsExt)
}

// Exposure probes:
//
//	aws-batch-job-definition-environment-value  (DescribeJobDefinitions -> jobDefinitions[].containerProperties.environment[].value / ...)
//	aws-batch-job-definition-command-parameters (DescribeJobDefinitions -> jobDefinitions[].parameters / containerProperties.command / ...)
//
// Because job definitions are not scoped to a job queue in the AWS data model,
// we enumerate all ACTIVE definitions region-wide. The prober deduplicates
// repeated (op, region, native_id) calls via cachedFetch, so each queue item
// drives at most one API call.
func fetchBatchDescribeJobDefinitionsExt(ctx context.Context, c *Client, region string, _ map[string]any) (any, error) {
	svc := batch.NewFromConfig(c.cfg)
	opt := func(o *batch.Options) { o.Region = region }

	var defs []types.JobDefinition
	var nextToken *string
	for {
		out, err := svc.DescribeJobDefinitions(ctx, &batch.DescribeJobDefinitionsInput{
			Status:    aws.String("ACTIVE"),
			NextToken: nextToken,
		}, opt)
		if err != nil {
			return nil, err
		}
		defs = append(defs, out.JobDefinitions...)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return jsonify(map[string]any{"jobDefinitions": defs}), nil
}

// Exposure probe:
//
//	aws-batch-submitted-job-values (DescribeJobs -> jobs[].parameters / container.environment[].value / ...)
//
// Lists jobs in the queue (covering RUNNING and SUCCEEDED states where
// resolved parameters/environment are populated) then describes them in
// batches of 100 (the API maximum).
func fetchBatchDescribeJobsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	queueID := itemStr(item, "arn", "native_id")
	if queueID == "" {
		return jsonify(map[string]any{"jobs": nil}), nil
	}

	svc := batch.NewFromConfig(c.cfg)
	opt := func(o *batch.Options) { o.Region = region }

	// Collect job IDs from all interesting statuses where environment/parameters
	// are fully resolved and retained on the job record.
	statuses := []types.JobStatus{
		types.JobStatusRunning,
		types.JobStatusSucceeded,
		types.JobStatusFailed,
	}

	var jobIDs []string
	for _, status := range statuses {
		var nextToken *string
		for {
			out, err := svc.ListJobs(ctx, &batch.ListJobsInput{
				JobQueue:  aws.String(queueID),
				JobStatus: status,
				NextToken: nextToken,
			}, opt)
			if err != nil {
				break // queue may be in a state where listing certain statuses fails; skip and continue
			}
			for _, s := range out.JobSummaryList {
				if s.JobId != nil {
					jobIDs = append(jobIDs, *s.JobId)
				}
			}
			if out.NextToken == nil {
				break
			}
			nextToken = out.NextToken
		}
	}

	if len(jobIDs) == 0 {
		return jsonify(map[string]any{"jobs": nil}), nil
	}

	// DescribeJobs accepts at most 100 IDs per call.
	var allJobs []any
	for i := 0; i < len(jobIDs); i += 100 {
		end := i + 100
		if end > len(jobIDs) {
			end = len(jobIDs)
		}
		out, err := svc.DescribeJobs(ctx, &batch.DescribeJobsInput{
			Jobs: jobIDs[i:end],
		}, opt)
		if err != nil {
			return nil, err
		}
		for _, j := range out.Jobs {
			allJobs = append(allJobs, j)
		}
	}

	return jsonify(map[string]any{"jobs": allJobs}), nil
}
