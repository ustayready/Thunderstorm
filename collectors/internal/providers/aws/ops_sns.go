package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func init() { register("sns:ListTopics", opSNSListTopics) }

// opSNSListTopics enumerates SNS topics (read-only).
func opSNSListTopics(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := sns.NewFromConfig(c.cfg)
	p := sns.NewListTopicsPaginator(svc, &sns.ListTopicsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *sns.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, t := range out.Topics {
			recs = append(recs, Record{
				"topic_arn": aws.ToString(t.TopicArn),
			})
		}
	}
	return recs, nil
}
