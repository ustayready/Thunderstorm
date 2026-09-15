package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
)

func init() {
	registerFetcher("GetBranch", "aws:amplify:app", fetchAmplifyGetBranchExt)
	registerFetcher("GetWebhook", "aws:amplify:app", fetchAmplifyGetWebhookExt)
}

// fetchAmplifyGetBranchExt implements the exposure probe for
// aws-amplify-branch-environment-variables (GetBranch -> branch.environmentVariables.<value>).
//
// GetBranch requires both appId and branchName. The manifest only enumerates
// aws:amplify:app resources, so branchName is not present in the inventory item.
// We enumerate branches via ListBranches(appId) and call GetBranch for each,
// returning all branches as a slice so the prober can walk each one.
func fetchAmplifyGetBranchExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	appID := itemStr(item, "native_id", "arn")
	svc := amplify.NewFromConfig(c.cfg)
	optFn := func(o *amplify.Options) { o.Region = region }

	// Enumerate branches for this app.
	var branches []string
	var nextToken *string
	for {
		listOut, err := svc.ListBranches(ctx, &amplify.ListBranchesInput{
			AppId:     aws.String(appID),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListBranches: %w", err)
		}
		for _, b := range listOut.Branches {
			if b.BranchName != nil {
				branches = append(branches, *b.BranchName)
			}
		}
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	// Fetch detail for each branch and collect results.
	var results []any
	for _, branchName := range branches {
		branchName := branchName
		out, err := svc.GetBranch(ctx, &amplify.GetBranchInput{
			AppId:      aws.String(appID),
			BranchName: aws.String(branchName),
		}, optFn)
		if err != nil {
			// A branch disappearing mid-scan is expected; skip it.
			continue
		}
		results = append(results, jsonify(out))
	}

	return results, nil
}

// fetchAmplifyGetWebhookExt implements the exposure probe for
// aws-amplify-webhook-url-output (GetWebhook -> webhook.webhookUrl).
//
// GetWebhook requires a webhookId that is not present in the app inventory item.
// We enumerate webhooks via ListWebhooks(appId) and call GetWebhook for each,
// returning all webhook details as a slice.
func fetchAmplifyGetWebhookExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	appID := itemStr(item, "native_id", "arn")
	svc := amplify.NewFromConfig(c.cfg)
	optFn := func(o *amplify.Options) { o.Region = region }

	// Enumerate webhooks for this app.
	var webhookIDs []string
	var nextToken *string
	for {
		listOut, err := svc.ListWebhooks(ctx, &amplify.ListWebhooksInput{
			AppId:     aws.String(appID),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListWebhooks: %w", err)
		}
		for _, wh := range listOut.Webhooks {
			if wh.WebhookId != nil {
				webhookIDs = append(webhookIDs, *wh.WebhookId)
			}
		}
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	// Fetch detail for each webhook and collect results.
	var results []any
	for _, webhookID := range webhookIDs {
		webhookID := webhookID
		out, err := svc.GetWebhook(ctx, &amplify.GetWebhookInput{
			WebhookId: aws.String(webhookID),
		}, optFn)
		if err != nil {
			// A webhook disappearing mid-scan is expected; skip it.
			continue
		}
		results = append(results, jsonify(out))
	}

	return results, nil
}
