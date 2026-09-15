package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
)

func init() { register("lightsail:GetInstances", opLightsailGetInstances) }

// opLightsailGetInstances enumerates Lightsail instances (read-only).
func opLightsailGetInstances(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := lightsail.NewFromConfig(c.cfg)
	out, err := svc.GetInstances(ctx, &lightsail.GetInstancesInput{}, func(o *lightsail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, inst := range out.Instances {
		recs = append(recs, Record{
			"instance_name": aws.ToString(inst.Name),
			"arn":           aws.ToString(inst.Arn),
		})
	}
	return recs, nil
}
