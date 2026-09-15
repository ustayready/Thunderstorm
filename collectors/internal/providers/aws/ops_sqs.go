package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func init() { register("sqs:ListQueues", opSQSListQueues) }

// opSQSListQueues enumerates SQS queues (read-only).
// ListQueues returns queue URLs ([]string), not structs; the URL serves as the
// primary identifier. ARNs are not returned by this operation.
func opSQSListQueues(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := sqs.NewFromConfig(c.cfg)
	p := sqs.NewListQueuesPaginator(svc, &sqs.ListQueuesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *sqs.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, url := range out.QueueUrls {
			recs = append(recs, Record{
				"queue_url": url,
			})
		}
	}
	return recs, nil
}
