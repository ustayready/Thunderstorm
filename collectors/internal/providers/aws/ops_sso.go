package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

func init() { register("sso:ListInstances", opSSOListInstances) }

// opSSOListInstances enumerates IAM Identity Center instances (read-only).
func opSSOListInstances(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ssoadmin.NewFromConfig(c.cfg)
	p := ssoadmin.NewListInstancesPaginator(svc, &ssoadmin.ListInstancesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ssoadmin.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Instances {
			recs = append(recs, Record{
				"instance_arn":      aws.ToString(item.InstanceArn),
				"identity_store_id": aws.ToString(item.IdentityStoreId),
			})
		}
	}
	return recs, nil
}
