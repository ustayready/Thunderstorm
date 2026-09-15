package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:elasticache:cache_cluster", fetchElasticacheListTagsForResource)
}

// Exposure probe: aws-elasticache-resource-tags-value-config (ListTagsForResource -> TagList[].Value).
func fetchElasticacheListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := elasticache.NewFromConfig(c.cfg).ListTagsForResource(ctx, &elasticache.ListTagsForResourceInput{
		ResourceName: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *elasticache.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
