package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
)

func init() {
	registerFetcher("DescribeConfigurationRevision", "aws:mq:broker", fetchMqDescribeConfigurationRevisionExt)
}

// Exposure probe: aws-mq-configuration-revision-data (DescribeConfigurationRevision -> Data).
//
// The inventory item is a broker, so we first call DescribeBroker to retrieve
// the current configuration ID and revision number, then fetch the revision
// data which may contain base64-encoded XML with credentials or connection strings.
func fetchMqDescribeConfigurationRevisionExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := mq.NewFromConfig(c.cfg, func(o *mq.Options) { o.Region = region })

	brokerID := itemStr(item, "native_id", "arn")

	// Step 1: describe the broker to obtain the current configuration reference.
	descOut, err := svc.DescribeBroker(ctx, &mq.DescribeBrokerInput{
		BrokerId: aws.String(brokerID),
	})
	if err != nil {
		return nil, err
	}

	if descOut.Configurations == nil || descOut.Configurations.Current == nil {
		// Broker has no attached configuration (e.g. RabbitMQ without explicit config).
		return nil, nil
	}

	cur := descOut.Configurations.Current
	if cur.Id == nil || cur.Revision == nil {
		return nil, nil
	}

	// Step 2: fetch the configuration revision data.
	revOut, err := svc.DescribeConfigurationRevision(ctx, &mq.DescribeConfigurationRevisionInput{
		ConfigurationId:       cur.Id,
		ConfigurationRevision: aws.String(fmt.Sprintf("%d", *cur.Revision)),
	})
	if err != nil {
		return nil, err
	}

	return jsonify(revOut), nil
}
