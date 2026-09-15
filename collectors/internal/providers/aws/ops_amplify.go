package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
)

func init() { register("amplify:ListApps", opAmplifyListApps) }

// opAmplifyListApps enumerates Amplify apps (read-only).
func opAmplifyListApps(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := amplify.NewFromConfig(c.cfg)
	p := amplify.NewListAppsPaginator(svc, &amplify.ListAppsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *amplify.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Apps {
			recs = append(recs, Record{
				"app_id":  aws.ToString(item.AppId),
				"app_arn": aws.ToString(item.AppArn),
			})
		}
	}
	return recs, nil
}
