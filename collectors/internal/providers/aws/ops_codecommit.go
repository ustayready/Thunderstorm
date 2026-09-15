package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
)

func init() { register("codecommit:ListRepositories", opCodeCommitListRepositories) }

// opCodeCommitListRepositories enumerates CodeCommit repositories (read-only).
func opCodeCommitListRepositories(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := codecommit.NewFromConfig(c.cfg)
	p := codecommit.NewListRepositoriesPaginator(svc, &codecommit.ListRepositoriesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *codecommit.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, repo := range out.Repositories {
			recs = append(recs, Record{
				"repository_name": aws.ToString(repo.RepositoryName),
				"repository_id":   aws.ToString(repo.RepositoryId),
			})
		}
	}
	return recs, nil
}
