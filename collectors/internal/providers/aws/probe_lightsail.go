package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
)

func init() {
	registerFetcher("GetInstance", "aws:lightsail:instance", fetchLightsailGetInstance)
}

// Exposure probe: aws-lightsail-instance-tags-value-config (GetInstance -> instance.tags[].value).
func fetchLightsailGetInstance(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := lightsail.NewFromConfig(c.cfg).GetInstance(ctx, &lightsail.GetInstanceInput{
		InstanceName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *lightsail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
