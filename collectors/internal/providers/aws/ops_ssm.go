package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func init() { register("ssm:DescribeInstanceInformation", opSSMDescribeInstanceInformation) }

// opSSMDescribeInstanceInformation enumerates SSM managed instances (read-only).
func opSSMDescribeInstanceInformation(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ssm.NewFromConfig(c.cfg)
	p := ssm.NewDescribeInstanceInformationPaginator(svc, &ssm.DescribeInstanceInformationInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ssm.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, inst := range out.InstanceInformationList {
			instanceID := aws.ToString(inst.InstanceId)
			recs = append(recs, Record{
				"instance_id": instanceID,
				"arn":         fmt.Sprintf("arn:aws:ssm:%s::managed-instance/%s", region, instanceID),
			})
		}
	}
	return recs, nil
}
