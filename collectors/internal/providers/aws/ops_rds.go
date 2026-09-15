package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() { register("rds:DescribeDBInstances", opRDSDescribeDBInstances) }

// opRDSDescribeDBInstances enumerates RDS DB instances (read-only).
func opRDSDescribeDBInstances(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := rds.NewFromConfig(c.cfg)
	p := rds.NewDescribeDBInstancesPaginator(svc, &rds.DescribeDBInstancesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *rds.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.DBInstances {
			recs = append(recs, Record{
				"db_instance_identifier": aws.ToString(item.DBInstanceIdentifier),
				"arn":                    aws.ToString(item.DBInstanceArn),
			})
		}
	}
	return recs, nil
}
