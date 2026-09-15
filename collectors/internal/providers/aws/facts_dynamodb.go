package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func init() { registerFactCollector("dynamodb-resource-policy", "regional", collectDynamodbPolicies) }

// collectDynamodbPolicies emits DynamoDB table resource-based policies as
// resource_policy facts (CrossAccountTrust surface). Tables are listed per
// region; tables with no resource policy attached are silently skipped.
func collectDynamodbPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := dynamodb.NewFromConfig(c.cfg)
	ro := func(o *dynamodb.Options) { o.Region = region }
	start := s.n

	p := dynamodb.NewListTablesPaginator(svc, &dynamodb.ListTablesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, name := range out.TableNames {
			name := name
			// ListTables returns names only; DescribeTable is needed to get the ARN.
			desc, e := svc.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: aws.String(name),
			}, ro)
			if e != nil || desc.Table == nil {
				continue
			}
			tableArn := aws.ToString(desc.Table.TableArn)
			if tableArn == "" {
				continue
			}
			pol, e := svc.GetResourcePolicy(ctx, &dynamodb.GetResourcePolicyInput{
				ResourceArn: aws.String(tableArn),
			}, ro)
			if e != nil || pol.Policy == nil {
				continue // no policy on this table, or table deleted mid-scan
			}
			s.emitFact("resource_policy", "CrossAccountTrust", s.scopeRegion(region),
				tableArn, "", map[string]any{"policy": aws.ToString(pol.Policy)})
		}
	}
	return s.n - start, nil
}
