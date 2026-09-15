package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

func init() {
	registerFetcher("ListTags", "aws:cloudtrail:trail", fetchCloudtrailListTags)
}

// Exposure probe: aws-cloudtrail-trail-tags-value-config (ListTags -> ResourceTagList[].TagsList[].Value).
func fetchCloudtrailListTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := cloudtrail.NewFromConfig(c.cfg).ListTags(ctx, &cloudtrail.ListTagsInput{
		ResourceIdList: []string{itemStr(item, "arn", "native_id")},
	}, func(o *cloudtrail.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
