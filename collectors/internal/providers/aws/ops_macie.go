package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
)

func init() { register("macie:ListClassificationJobs", opMacieListClassificationJobs) }

// opMacieListClassificationJobs enumerates Macie classification jobs (read-only).
func opMacieListClassificationJobs(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := macie2.NewFromConfig(c.cfg)
	p := macie2.NewListClassificationJobsPaginator(svc, &macie2.ListClassificationJobsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *macie2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Items {
			recs = append(recs, Record{
				"job_id": aws.ToString(item.JobId),
			})
		}
	}
	return recs, nil
}
