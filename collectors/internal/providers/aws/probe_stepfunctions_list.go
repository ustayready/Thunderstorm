package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

func init() {
	registerListFetcher("DescribeExecution", listFetchStepfunctionsDescribeExecution)
	registerListFetcher("GetExecutionHistory", listFetchStepfunctionsGetExecutionHistory)
}

// listFetchStepfunctionsDescribeExecution enumerates all state machines in the
// region, then all executions per state machine, and returns the full
// DescribeExecution response for each (read-only); per-item errors are skipped.
func listFetchStepfunctionsDescribeExecution(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := sfn.NewFromConfig(c.cfg)
	ro := func(o *sfn.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate state machines.
	smp := sfn.NewListStateMachinesPaginator(svc, &sfn.ListStateMachinesInput{})
	for smp.HasMorePages() {
		smPage, err := smp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, sm := range smPage.StateMachines {
			if sm.StateMachineArn == nil {
				continue
			}

			// Step 2: enumerate executions for this state machine.
			ep := sfn.NewListExecutionsPaginator(svc, &sfn.ListExecutionsInput{
				StateMachineArn: sm.StateMachineArn,
			})
			for ep.HasMorePages() {
				ePage, err := ep.NextPage(ctx, ro)
				if err != nil {
					break // move to next state machine on error
				}
				for _, ex := range ePage.Executions {
					if ex.ExecutionArn == nil {
						continue
					}
					// Step 3: fetch full execution detail.
					d, e := svc.DescribeExecution(ctx, &sfn.DescribeExecutionInput{
						ExecutionArn: ex.ExecutionArn,
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

// listFetchStepfunctionsGetExecutionHistory enumerates all state machines in the
// region, then all executions per state machine, and returns each page of
// execution history events (read-only, includeExecutionData=true); per-item
// errors are skipped.
func listFetchStepfunctionsGetExecutionHistory(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := sfn.NewFromConfig(c.cfg)
	ro := func(o *sfn.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate state machines.
	smp := sfn.NewListStateMachinesPaginator(svc, &sfn.ListStateMachinesInput{})
	for smp.HasMorePages() {
		smPage, err := smp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, sm := range smPage.StateMachines {
			if sm.StateMachineArn == nil {
				continue
			}

			// Step 2: enumerate executions for this state machine.
			ep := sfn.NewListExecutionsPaginator(svc, &sfn.ListExecutionsInput{
				StateMachineArn: sm.StateMachineArn,
			})
			for ep.HasMorePages() {
				ePage, err := ep.NextPage(ctx, ro)
				if err != nil {
					break // move to next state machine on error
				}
				for _, ex := range ePage.Executions {
					if ex.ExecutionArn == nil {
						continue
					}
					// Step 3: stream execution history pages; each page is
					// appended so the prober can walk events[]*EventDetails.
					hp := sfn.NewGetExecutionHistoryPaginator(svc, &sfn.GetExecutionHistoryInput{
						ExecutionArn:         ex.ExecutionArn,
						IncludeExecutionData: aws.Bool(true),
					})
					for hp.HasMorePages() {
						hPage, e := hp.NextPage(ctx, ro)
						if e != nil {
							break // per-execution error — skip remaining pages
						}
						out = append(out, jsonify(hPage))
					}
				}
			}
		}
	}
	return out, nil
}
