package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
)

func init() {
	registerListFetcher("GetDeployment", listFetchCodedeployGetDeployment)
}

// listFetchCodedeployGetDeployment enumerates all CodeDeploy applications in the
// region, then all deployment IDs per application, and fetches full detail for
// each via GetDeployment (read-only); per-item errors are skipped.
func listFetchCodedeployGetDeployment(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := codedeploy.NewFromConfig(c.cfg)
	ro := func(o *codedeploy.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate all applications.
	ap := codedeploy.NewListApplicationsPaginator(svc, &codedeploy.ListApplicationsInput{})
	for ap.HasMorePages() {
		aPage, err := ap.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, appName := range aPage.Applications {
			appName := appName

			// Step 2: enumerate deployment IDs for this application.
			dp := codedeploy.NewListDeploymentsPaginator(svc, &codedeploy.ListDeploymentsInput{
				ApplicationName: aws.String(appName),
			})
			for dp.HasMorePages() {
				dPage, err := dp.NextPage(ctx, ro)
				if err != nil {
					break // move to next application on error
				}
				for _, deploymentID := range dPage.Deployments {
					deploymentID := deploymentID

					// Step 3: fetch full deployment detail.
					d, e := svc.GetDeployment(ctx, &codedeploy.GetDeploymentInput{
						DeploymentId: aws.String(deploymentID),
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
