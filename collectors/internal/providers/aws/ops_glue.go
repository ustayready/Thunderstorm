package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
)

func init() { register("glue:GetJobs", opGlueGetJobs) }

// opGlueGetJobs enumerates Glue jobs (read-only).
func opGlueGetJobs(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := glue.NewFromConfig(c.cfg)
	p := glue.NewGetJobsPaginator(svc, &glue.GetJobsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *glue.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, job := range out.Jobs {
			rec := Record{
				"job_name": aws.ToString(job.Name),
			}
			if job.Role != nil {
				rec["role_arn"] = aws.ToString(job.Role)
			}
			recs = append(recs, rec)
		}
	}
	return recs, nil
}
