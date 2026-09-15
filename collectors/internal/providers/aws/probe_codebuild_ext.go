package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
)

func init() {
	registerFetcher("BatchGetBuilds", "aws:codebuild:project", fetchCodeBuildBatchGetBuildsExt)
	registerFetcher("GetResourcePolicy", "aws:codebuild:project", fetchCodeBuildGetResourcePolicyExt)
	registerFetcher("ListSourceCredentials", "aws:codebuild:project", fetchCodeBuildListSourceCredentialsExt)
}

// fetchCodeBuildBatchGetBuildsExt implements the exposure probes for:
//   - aws-codebuild-build-override-environment-value  (BatchGetBuilds -> builds[].environment.environmentVariables[].value)
//   - aws-codebuild-exported-environment-variable-output (BatchGetBuilds -> builds[].exportedEnvironmentVariables[].value)
//
// Enumerates recent builds for the project via ListBuildsForProject, then
// fetches their full records via BatchGetBuilds (up to 100 IDs per call).
// Build records retain resolved environment variables and exported values even
// after the build completes, making them a durable source of plaintext secrets.
func fetchCodeBuildBatchGetBuildsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	projectName := itemStr(item, "native_id", "arn")
	if projectName == "" {
		return jsonify(map[string]any{"builds": nil}), nil
	}

	svc := codebuild.NewFromConfig(c.cfg)
	opt := func(o *codebuild.Options) { o.Region = region }

	// Collect build IDs for this project. The API returns at most 100 per page.
	var buildIDs []string
	var nextToken *string
	for {
		listOut, err := svc.ListBuildsForProject(ctx, &codebuild.ListBuildsForProjectInput{
			ProjectName: aws.String(projectName),
			NextToken:   nextToken,
		}, opt)
		if err != nil {
			return nil, err
		}
		buildIDs = append(buildIDs, listOut.Ids...)
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	if len(buildIDs) == 0 {
		return jsonify(map[string]any{"builds": nil}), nil
	}

	// BatchGetBuilds accepts at most 100 IDs per call.
	var allBuilds []any
	for i := 0; i < len(buildIDs); i += 100 {
		end := i + 100
		if end > len(buildIDs) {
			end = len(buildIDs)
		}
		out, err := svc.BatchGetBuilds(ctx, &codebuild.BatchGetBuildsInput{
			Ids: buildIDs[i:end],
		}, opt)
		if err != nil {
			return nil, err
		}
		for _, b := range out.Builds {
			allBuilds = append(allBuilds, b)
		}
	}

	return jsonify(map[string]any{"builds": allBuilds}), nil
}

// fetchCodeBuildGetResourcePolicyExt implements the exposure probe for
// GetResourcePolicy on a CodeBuild project ARN. Resource policies can contain
// cross-account principal statements or condition values that expose credentials
// or sensitive configuration.
func fetchCodeBuildGetResourcePolicyExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	arn := itemStr(item, "arn", "native_id")
	if arn == "" {
		return nil, nil
	}

	svc := codebuild.NewFromConfig(c.cfg)
	opt := func(o *codebuild.Options) { o.Region = region }

	out, err := svc.GetResourcePolicy(ctx, &codebuild.GetResourcePolicyInput{
		ResourceArn: aws.String(arn),
	}, opt)
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchCodeBuildListSourceCredentialsExt implements the exposure probe for
// ListSourceCredentials. Source credential records include the ARN and auth
// type for stored OAuth tokens and personal access tokens used to connect
// CodeBuild to source providers (GitHub, Bitbucket, GitLab). The token ARN
// itself can be used to resolve the underlying secret via Secrets Manager.
// This call is region-wide and requires no per-item parameter.
func fetchCodeBuildListSourceCredentialsExt(ctx context.Context, c *Client, region string, _ map[string]any) (any, error) {
	svc := codebuild.NewFromConfig(c.cfg)
	opt := func(o *codebuild.Options) { o.Region = region }

	out, err := svc.ListSourceCredentials(ctx, &codebuild.ListSourceCredentialsInput{}, opt)
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
