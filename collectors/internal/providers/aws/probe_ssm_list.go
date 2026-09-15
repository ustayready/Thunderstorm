package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func init() {
	registerListFetcher("GetDocument", listFetchSsmGetDocument)
	registerListFetcher("GetCommandInvocation", listFetchSsmGetCommandInvocation)
	registerListFetcher("GetAutomationExecution", listFetchSsmGetAutomationExecution)
	registerListFetcher("DescribeAssociation", listFetchSsmDescribeAssociation)
	registerListFetcher("GetMaintenanceWindowTask", listFetchSsmGetMaintenanceWindowTask)
	registerListFetcher("GetOpsItem", listFetchSsmGetOpsItem)
}

// listFetchSsmGetDocument enumerates this account's OWN SSM documents in a region
// and returns each document's full content (read-only); the prober applies
// response_path (Content) to each result. Owner=Self excludes the ~1500 AWS-owned
// public runbooks — those are not this account's exposure and would swamp findings.
func listFetchSsmGetDocument(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ssm.NewFromConfig(c.cfg)
	ro := func(o *ssm.Options) { o.Region = region }
	var out []any
	p := ssm.NewListDocumentsPaginator(svc, &ssm.ListDocumentsInput{
		Filters: []ssmtypes.DocumentKeyValuesFilter{
			{Key: aws.String("Owner"), Values: []string{"Self"}},
		},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, doc := range page.DocumentIdentifiers {
			if doc.Name == nil {
				continue
			}
			d, e := svc.GetDocument(ctx, &ssm.GetDocumentInput{
				Name:           doc.Name,
				DocumentFormat: ssmtypes.DocumentFormatYaml,
			}, ro)
			if e != nil {
				continue // permission / not-found — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchSsmGetCommandInvocation enumerates all command invocations in a
// region and fetches the full per-invocation detail (stdout/stderr) for each.
func listFetchSsmGetCommandInvocation(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ssm.NewFromConfig(c.cfg)
	ro := func(o *ssm.Options) { o.Region = region }
	var out []any
	p := ssm.NewListCommandInvocationsPaginator(svc, &ssm.ListCommandInvocationsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, inv := range page.CommandInvocations {
			if inv.CommandId == nil || inv.InstanceId == nil {
				continue
			}
			d, e := svc.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
				CommandId:  inv.CommandId,
				InstanceId: inv.InstanceId,
			}, ro)
			if e != nil {
				continue
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchSsmGetAutomationExecution enumerates all automation executions in a
// region and fetches each full execution record (Parameters / Outputs).
func listFetchSsmGetAutomationExecution(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ssm.NewFromConfig(c.cfg)
	ro := func(o *ssm.Options) { o.Region = region }
	var out []any
	p := ssm.NewDescribeAutomationExecutionsPaginator(svc, &ssm.DescribeAutomationExecutionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, meta := range page.AutomationExecutionMetadataList {
			if meta.AutomationExecutionId == nil {
				continue
			}
			d, e := svc.GetAutomationExecution(ctx, &ssm.GetAutomationExecutionInput{
				AutomationExecutionId: meta.AutomationExecutionId,
			}, ro)
			if e != nil {
				continue
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchSsmDescribeAssociation enumerates all State Manager associations in
// a region and fetches the full description (including Parameters) for each.
func listFetchSsmDescribeAssociation(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ssm.NewFromConfig(c.cfg)
	ro := func(o *ssm.Options) { o.Region = region }
	var out []any
	p := ssm.NewListAssociationsPaginator(svc, &ssm.ListAssociationsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, assoc := range page.Associations {
			if assoc.AssociationId == nil {
				continue
			}
			d, e := svc.DescribeAssociation(ctx, &ssm.DescribeAssociationInput{
				AssociationId: assoc.AssociationId,
			}, ro)
			if e != nil {
				continue
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchSsmGetMaintenanceWindowTask enumerates all maintenance windows in a
// region, then all tasks within each window, and fetches the full task record
// (TaskInvocationParameters) for each one.
func listFetchSsmGetMaintenanceWindowTask(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ssm.NewFromConfig(c.cfg)
	ro := func(o *ssm.Options) { o.Region = region }
	var out []any

	// Page through all maintenance windows.
	wp := ssm.NewDescribeMaintenanceWindowsPaginator(svc, &ssm.DescribeMaintenanceWindowsInput{})
	for wp.HasMorePages() {
		wPage, err := wp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, win := range wPage.WindowIdentities {
			if win.WindowId == nil {
				continue
			}
			// Page through all tasks in this window.
			tp := ssm.NewDescribeMaintenanceWindowTasksPaginator(svc, &ssm.DescribeMaintenanceWindowTasksInput{
				WindowId: win.WindowId,
			})
			for tp.HasMorePages() {
				tPage, err := tp.NextPage(ctx, ro)
				if err != nil {
					break // move to next window on error
				}
				for _, task := range tPage.Tasks {
					if task.WindowId == nil || task.WindowTaskId == nil {
						continue
					}
					d, e := svc.GetMaintenanceWindowTask(ctx, &ssm.GetMaintenanceWindowTaskInput{
						WindowId:     task.WindowId,
						WindowTaskId: task.WindowTaskId,
					}, ro)
					if e != nil {
						continue
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}

// listFetchSsmGetOpsItem enumerates all OpsItems in a region and fetches the
// full record (OperationalData) for each one.
func listFetchSsmGetOpsItem(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ssm.NewFromConfig(c.cfg)
	ro := func(o *ssm.Options) { o.Region = region }
	var out []any
	p := ssm.NewDescribeOpsItemsPaginator(svc, &ssm.DescribeOpsItemsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, summary := range page.OpsItemSummaries {
			if summary.OpsItemId == nil {
				continue
			}
			d, e := svc.GetOpsItem(ctx, &ssm.GetOpsItemInput{
				OpsItemId: aws.String(*summary.OpsItemId),
			}, ro)
			if e != nil {
				continue
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}
