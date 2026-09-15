package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func init() {
	registerFetcher("ListCommands", "aws:ssm:managed-instance", fetchSSMListCommandsExt)
}

// Exposure probe: aws-ssm-command-parameters-config (ListCommands -> Commands[].Parameters).
// Filters by the managed node's InstanceId so only commands targeting this node are returned.
// The Parameters field of each Command may contain plaintext credentials passed inline.
func fetchSSMListCommandsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ssm.NewFromConfig(c.cfg).ListCommands(ctx, &ssm.ListCommandsInput{
		InstanceId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *ssm.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
