package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
)

func init() { register("codedeploy:ListApplications", opCodeDeployListApplications) }

// opCodeDeployListApplications enumerates CodeDeploy applications (read-only).
func opCodeDeployListApplications(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := codedeploy.NewFromConfig(c.cfg)
	p := codedeploy.NewListApplicationsPaginator(svc, &codedeploy.ListApplicationsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *codedeploy.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, name := range out.Applications {
			recs = append(recs, Record{
				"application_name": name,
			})
		}
	}
	return recs, nil
}
