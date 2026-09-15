package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() {
	registerFetcher("DescribeSnapshots", "aws:ebs:snapshot", fetchEbsDescribeSnapshots)
}

// Exposure probe: aws-ebs-snapshot-description-config + aws-ebs-snapshot-tags-value-config
// (DescribeSnapshots -> Snapshots[].Description / Snapshots[].Tags[].Value).
func fetchEbsDescribeSnapshots(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ec2.NewFromConfig(c.cfg).DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		SnapshotIds: []string{itemStr(item, "native_id", "arn")},
	}, func(o *ec2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
