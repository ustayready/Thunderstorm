package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/ram/types"
)

func init() {
	registerFetcher("GetResourceShares", "aws:ram:resource_share", fetchRAMGetResourceShares)
}

// Exposure probe: aws-ram-resource-share-tags-value-config (GetResourceShares -> resourceShares[].tags[].value).
func fetchRAMGetResourceShares(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	arn := itemStr(item, "arn", "native_id")
	out, err := ram.NewFromConfig(c.cfg).GetResourceShares(ctx, &ram.GetResourceSharesInput{
		ResourceOwner:     types.ResourceOwnerSelf,
		ResourceShareArns: []string{arn},
	}, func(o *ram.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
