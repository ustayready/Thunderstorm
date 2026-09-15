package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

func init() { register("ecr:DescribeRepositories", opECRDescribeRepositories) }

// opECRDescribeRepositories enumerates ECR repositories (read-only).
func opECRDescribeRepositories(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := ecr.NewFromConfig(c.cfg)
	p := ecr.NewDescribeRepositoriesPaginator(svc, &ecr.DescribeRepositoriesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *ecr.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, repo := range out.Repositories {
			recs = append(recs, Record{
				"repository_name": aws.ToString(repo.RepositoryName),
				"arn":             aws.ToString(repo.RepositoryArn),
			})
		}
	}
	return recs, nil
}
