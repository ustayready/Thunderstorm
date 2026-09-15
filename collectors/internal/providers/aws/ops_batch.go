package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
)

func init() { register("batch:DescribeJobQueues", opBatchDescribeJobQueues) }

// opBatchDescribeJobQueues enumerates Batch job queues (read-only).
func opBatchDescribeJobQueues(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := batch.NewFromConfig(c.cfg)
	p := batch.NewDescribeJobQueuesPaginator(svc, &batch.DescribeJobQueuesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *batch.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, q := range out.JobQueues {
			recs = append(recs, Record{
				"job_queue_name": aws.ToString(q.JobQueueName),
				"job_queue_arn":  aws.ToString(q.JobQueueArn),
			})
		}
	}
	return recs, nil
}
