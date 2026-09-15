package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:codeartifact:repository", fetchCodeArtifactListTagsForResource)
}

// Exposure probe: aws-codeartifact-resource-tags-value-config (ListTagsForResource -> tags[].value).
func fetchCodeArtifactListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codeartifact.NewFromConfig(c.cfg).ListTagsForResource(ctx, &codeartifact.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *codeartifact.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
