package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:athena:workgroup", fetchAthenaListTagsForResource)
}

// Exposure probe: aws-athena-resource-tags-value-config (ListTagsForResource -> Tags[].Value).
func fetchAthenaListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := athena.NewFromConfig(c.cfg).ListTagsForResource(ctx, &athena.ListTagsForResourceInput{
		ResourceARN: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *athena.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
