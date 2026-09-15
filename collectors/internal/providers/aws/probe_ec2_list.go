package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() {
	registerListFetcher("DescribeLaunchTemplateVersions", listFetchEc2DescribeLaunchTemplateVersions)
}

// listFetchEc2DescribeLaunchTemplateVersions enumerates all launch templates in
// the region, then fetches every version of each (Versions="$All") and appends
// the full DescribeLaunchTemplateVersions page responses so the prober can walk
// LaunchTemplateVersions[].LaunchTemplateData.UserData via response_path.
// Read-only; per-template errors are skipped.
func listFetchEc2DescribeLaunchTemplateVersions(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ec2.NewFromConfig(c.cfg)
	ro := func(o *ec2.Options) { o.Region = region }

	var out []any

	// Step 1: list all launch templates in the region.
	ltp := ec2.NewDescribeLaunchTemplatesPaginator(svc, &ec2.DescribeLaunchTemplatesInput{})
	for ltp.HasMorePages() {
		ltPage, err := ltp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}

		// Step 2: for each template, retrieve all versions.
		for _, lt := range ltPage.LaunchTemplates {
			vp := ec2.NewDescribeLaunchTemplateVersionsPaginator(svc, &ec2.DescribeLaunchTemplateVersionsInput{
				LaunchTemplateId: lt.LaunchTemplateId,
				Versions:         []string{"$All"},
			})
			for vp.HasMorePages() {
				page, err := vp.NextPage(ctx, ro)
				if err != nil {
					break // per-template/access error — skip remaining pages
				}
				out = append(out, jsonify(page))
			}
		}
	}

	return out, nil
}
