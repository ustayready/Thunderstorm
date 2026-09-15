package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() { register("ebs:DescribeSnapshots", opEBSDescribeSnapshots) }

// opEBSDescribeSnapshots enumerates EBS snapshots owned by this account (read-only).
func opEBSDescribeSnapshots(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ec2.NewFromConfig(c.cfg)
	p := ec2.NewDescribeSnapshotsPaginator(svc, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ec2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, snap := range out.Snapshots {
			id := aws.ToString(snap.SnapshotId)
			arn := fmt.Sprintf("arn:aws:ec2:%s::snapshot/%s", region, id)
			recs = append(recs, Record{
				"snapshot_id": id,
				"arn":         arn,
			})
		}
	}
	return recs, nil
}
