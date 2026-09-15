package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
)

func init() { register("fsx:DescribeFileSystems", opFSxDescribeFileSystems) }

// opFSxDescribeFileSystems enumerates FSx file systems (read-only).
func opFSxDescribeFileSystems(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := fsx.NewFromConfig(c.cfg)
	p := fsx.NewDescribeFileSystemsPaginator(svc, &fsx.DescribeFileSystemsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *fsx.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.FileSystems {
			recs = append(recs, Record{
				"file_system_id": aws.ToString(item.FileSystemId),
				"resource_arn":   aws.ToString(item.ResourceARN),
			})
		}
	}
	return recs, nil
}
