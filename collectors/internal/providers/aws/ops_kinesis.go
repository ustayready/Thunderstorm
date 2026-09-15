package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

func init() { register("kinesis:ListStreams", opKinesisListStreams) }

// opKinesisListStreams enumerates Kinesis Data Streams (read-only).
// ListStreams returns stream names ([]string); ARNs are not returned by this
// operation so stream_name serves as the primary identifier.
func opKinesisListStreams(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := kinesis.NewFromConfig(c.cfg)
	p := kinesis.NewListStreamsPaginator(svc, &kinesis.ListStreamsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *kinesis.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, name := range out.StreamNames {
			recs = append(recs, Record{
				"stream_name": name,
			})
		}
	}
	return recs, nil
}
