package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
)

func init() { register("ds:DescribeDirectories", opDSDescribeDirectories) }

// opDSDescribeDirectories enumerates Directory Service directories (read-only).
// DescribeDirectories does not return an ARN; only directory_id is captured.
func opDSDescribeDirectories(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := directoryservice.NewFromConfig(c.cfg)
	var nextToken *string
	var recs []Record
	for {
		out, err := svc.DescribeDirectories(ctx, &directoryservice.DescribeDirectoriesInput{
			NextToken: nextToken,
		}, func(o *directoryservice.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, d := range out.DirectoryDescriptions {
			recs = append(recs, Record{
				"directory_id": aws.ToString(d.DirectoryId),
			})
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return recs, nil
}
