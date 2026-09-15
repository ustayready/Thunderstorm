package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
)

func init() {
	registerListFetcher("DescribeStep", listFetchEmrDescribeStep)
}

// listFetchEmrDescribeStep enumerates all EMR clusters in the region, then all
// steps per cluster, and fetches full detail for each via DescribeStep
// (read-only); per-item errors are skipped.
func listFetchEmrDescribeStep(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := emr.NewFromConfig(c.cfg)
	ro := func(o *emr.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate all clusters.
	cp := emr.NewListClustersPaginator(svc, &emr.ListClustersInput{})
	for cp.HasMorePages() {
		cPage, err := cp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, cl := range cPage.Clusters {
			if cl.Id == nil {
				continue
			}
			clusterID := aws.ToString(cl.Id)

			// Step 2: enumerate steps for this cluster.
			sp := emr.NewListStepsPaginator(svc, &emr.ListStepsInput{
				ClusterId: aws.String(clusterID),
			})
			for sp.HasMorePages() {
				sPage, err := sp.NextPage(ctx, ro)
				if err != nil {
					break // move to next cluster on error
				}
				for _, step := range sPage.Steps {
					if step.Id == nil {
						continue
					}

					// Step 3: fetch full step detail.
					d, e := svc.DescribeStep(ctx, &emr.DescribeStepInput{
						ClusterId: aws.String(clusterID),
						StepId:    step.Id,
					}, ro)
					if e != nil {
						continue // per-item error — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}
