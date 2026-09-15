package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:beanstalk:environment", fetchBeanstalkListTagsForResource)
}

// Exposure probe: aws-beanstalk-resource-tags-value-config (ListTagsForResource -> ResourceTags[].Value).
func fetchBeanstalkListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := elasticbeanstalk.NewFromConfig(c.cfg).ListTagsForResource(ctx, &elasticbeanstalk.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *elasticbeanstalk.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
