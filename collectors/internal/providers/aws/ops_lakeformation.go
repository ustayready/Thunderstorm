package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
)

func init() { register("lakeformation:ListResources", opLakeFormationListResources) }

// opLakeFormationListResources enumerates Lake Formation registered data lake
// resources (read-only). Each entry is an S3 location registered with Lake
// Formation; ResourceArn doubles as both the identifier and the ARN.
func opLakeFormationListResources(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := lakeformation.NewFromConfig(c.cfg)
	p := lakeformation.NewListResourcesPaginator(svc, &lakeformation.ListResourcesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *lakeformation.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.ResourceInfoList {
			recs = append(recs, Record{
				"resource_arn": aws.ToString(item.ResourceArn),
			})
		}
	}
	return recs, nil
}
