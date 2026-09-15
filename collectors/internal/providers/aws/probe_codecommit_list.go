package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/codecommit"
)

func init() {
	registerListFetcher("GetCommit", listFetchCodecommitGetCommit)
	registerListFetcher("GetCommentsForPullRequest", listFetchCodecommitGetCommentsForPullRequest)
}

// listFetchCodecommitGetCommit enumerates all CodeCommit repositories in the
// region, then all branches per repository, and fetches the tip commit via
// GetCommit for each branch (read-only); per-item errors are skipped.
func listFetchCodecommitGetCommit(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := codecommit.NewFromConfig(c.cfg)
	ro := func(o *codecommit.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate repositories.
	rp := codecommit.NewListRepositoriesPaginator(svc, &codecommit.ListRepositoriesInput{})
	for rp.HasMorePages() {
		rPage, err := rp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, repo := range rPage.Repositories {
			if repo.RepositoryName == nil {
				continue
			}
			repoName := repo.RepositoryName

			// Step 2: enumerate branches for this repository.
			bp := codecommit.NewListBranchesPaginator(svc, &codecommit.ListBranchesInput{
				RepositoryName: repoName,
			})
			for bp.HasMorePages() {
				bPage, err := bp.NextPage(ctx, ro)
				if err != nil {
					break // move to next repository on error
				}
				for _, branchName := range bPage.Branches {
					branchName := branchName

					// Step 3: get the branch's tip commit ID.
					br, e := svc.GetBranch(ctx, &codecommit.GetBranchInput{
						RepositoryName: repoName,
						BranchName:     &branchName,
					}, ro)
					if e != nil || br.Branch == nil || br.Branch.CommitId == nil {
						continue // per-item error — skip
					}

					// Step 4: fetch full commit detail.
					d, e := svc.GetCommit(ctx, &codecommit.GetCommitInput{
						RepositoryName: repoName,
						CommitId:       br.Branch.CommitId,
					}, ro)
					if e != nil {
						continue // per-item error — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}

// listFetchCodecommitGetCommentsForPullRequest enumerates all CodeCommit
// repositories in the region, then all pull requests per repository, and
// fetches comments for each pull request via GetCommentsForPullRequest
// (read-only); per-item errors are skipped.
func listFetchCodecommitGetCommentsForPullRequest(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := codecommit.NewFromConfig(c.cfg)
	ro := func(o *codecommit.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate repositories.
	rp := codecommit.NewListRepositoriesPaginator(svc, &codecommit.ListRepositoriesInput{})
	for rp.HasMorePages() {
		rPage, err := rp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, repo := range rPage.Repositories {
			if repo.RepositoryName == nil {
				continue
			}
			repoName := repo.RepositoryName

			// Step 2: enumerate pull requests for this repository.
			pp := codecommit.NewListPullRequestsPaginator(svc, &codecommit.ListPullRequestsInput{
				RepositoryName: repoName,
			})
			for pp.HasMorePages() {
				pPage, err := pp.NextPage(ctx, ro)
				if err != nil {
					break // move to next repository on error
				}
				for _, prID := range pPage.PullRequestIds {
					prID := prID

					// Step 3: fetch all comment pages for this pull request.
					cp := codecommit.NewGetCommentsForPullRequestPaginator(svc, &codecommit.GetCommentsForPullRequestInput{
						PullRequestId:  &prID,
						RepositoryName: repoName,
					})
					for cp.HasMorePages() {
						cPage, err := cp.NextPage(ctx, ro)
						if err != nil {
							break // move to next pull request on error
						}
						out = append(out, jsonify(cPage))
					}
				}
			}
		}
	}
	return out, nil
}
