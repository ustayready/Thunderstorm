package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
)

func init() { register("beanstalk:DescribeEnvironments", opBeanstalkDescribeEnvironments) }

// opBeanstalkDescribeEnvironments enumerates Elastic Beanstalk environments (read-only).
func opBeanstalkDescribeEnvironments(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := elasticbeanstalk.NewFromConfig(c.cfg)
	out, err := svc.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{}, func(o *elasticbeanstalk.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, item := range out.Environments {
		recs = append(recs, Record{
			"environment_name": aws.ToString(item.EnvironmentName),
			"environment_arn":  aws.ToString(item.EnvironmentArn),
		})
	}
	return recs, nil
}
