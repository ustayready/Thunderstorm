package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

func init() { register("elasticfilesystem:DescribeFileSystems", opEFSDescribeFileSystems) }

// opEFSDescribeFileSystems enumerates EFS file systems (read-only).
func opEFSDescribeFileSystems(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := efs.NewFromConfig(c.cfg)
	p := efs.NewDescribeFileSystemsPaginator(svc, &efs.DescribeFileSystemsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *efs.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, fs := range out.FileSystems {
			recs = append(recs, Record{
				"file_system_id": aws.ToString(fs.FileSystemId),
				"arn":            aws.ToString(fs.FileSystemArn),
			})
		}
	}
	return recs, nil
}
