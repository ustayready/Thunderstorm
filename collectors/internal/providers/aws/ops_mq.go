package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
)

func init() { register("mq:ListBrokers", opMQListBrokers) }

// opMQListBrokers enumerates Amazon MQ brokers (read-only).
func opMQListBrokers(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := mq.NewFromConfig(c.cfg)
	p := mq.NewListBrokersPaginator(svc, &mq.ListBrokersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *mq.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, b := range out.BrokerSummaries {
			recs = append(recs, Record{
				"broker_id":  aws.ToString(b.BrokerId),
				"broker_arn": aws.ToString(b.BrokerArn),
			})
		}
	}
	return recs, nil
}
