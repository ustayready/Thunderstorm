package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
)

func init() { register("access-analyzer:ListAnalyzers", opAccessAnalyzerListAnalyzers) }

// opAccessAnalyzerListAnalyzers enumerates IAM Access Analyzer analyzers (read-only).
func opAccessAnalyzerListAnalyzers(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := accessanalyzer.NewFromConfig(c.cfg)
	p := accessanalyzer.NewListAnalyzersPaginator(svc, &accessanalyzer.ListAnalyzersInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *accessanalyzer.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Analyzers {
			recs = append(recs, Record{
				"analyzer_name": aws.ToString(item.Name),
				"arn":           aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
