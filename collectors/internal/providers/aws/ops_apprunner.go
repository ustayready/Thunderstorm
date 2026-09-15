package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
)

func init() { register("apprunner:ListServices", opAppRunnerListServices) }

// opAppRunnerListServices enumerates App Runner services (read-only).
func opAppRunnerListServices(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := apprunner.NewFromConfig(c.cfg)
	p := apprunner.NewListServicesPaginator(svc, &apprunner.ListServicesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *apprunner.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.ServiceSummaryList {
			recs = append(recs, Record{
				"service_name": aws.ToString(item.ServiceName),
				"service_arn":  aws.ToString(item.ServiceArn),
			})
		}
	}
	return recs, nil
}
