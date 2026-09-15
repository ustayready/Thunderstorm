package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

func init() {
	registerListFetcher("DescribeLaunchConfigurations", listFetchAutoscalingDescribeLaunchConfigurations)
}

// listFetchAutoscalingDescribeLaunchConfigurations enumerates all launch
// configurations in the region and returns each one as a jsonified response
// (read-only). The prober applies the site's response_path
// (LaunchConfigurations[].UserData) to each item.
func listFetchAutoscalingDescribeLaunchConfigurations(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := autoscaling.NewFromConfig(c.cfg)
	ro := func(o *autoscaling.Options) { o.Region = region }
	var out []any
	p := autoscaling.NewDescribeLaunchConfigurationsPaginator(svc, &autoscaling.DescribeLaunchConfigurationsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, lc := range page.LaunchConfigurations {
			out = append(out, jsonify(lc))
		}
	}
	return out, nil
}
