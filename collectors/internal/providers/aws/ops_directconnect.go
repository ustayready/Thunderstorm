package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
)

func init() { register("directconnect:DescribeConnections", opDirectConnectDescribeConnections) }

// opDirectConnectDescribeConnections enumerates Direct Connect connections (read-only).
func opDirectConnectDescribeConnections(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := directconnect.NewFromConfig(c.cfg)
	var nextToken *string
	var recs []Record
	for {
		out, err := svc.DescribeConnections(ctx, &directconnect.DescribeConnectionsInput{
			NextToken: nextToken,
		}, func(o *directconnect.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, conn := range out.Connections {
			id := aws.ToString(conn.ConnectionId)
			acct := aws.ToString(conn.OwnerAccount)
			arn := fmt.Sprintf("arn:aws:directconnect:%s:%s:dxcon/%s", region, acct, id)
			recs = append(recs, Record{
				"connection_id": id,
				"arn":           arn,
			})
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return recs, nil
}
