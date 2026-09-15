package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
)

func init() {
	registerFetcher("GetQueryExecution", "aws:athena:workgroup", fetchAthenaGetQueryExecutionExt)
	registerFetcher("GetQueryResults", "aws:athena:workgroup", fetchAthenaGetQueryResultsExt)
	registerFetcher("GetNamedQuery", "aws:athena:workgroup", fetchAthenaGetNamedQueryExt)
	registerFetcher("GetPreparedStatement", "aws:athena:workgroup", fetchAthenaGetPreparedStatementExt)
	registerFetcher("ExportNotebook", "aws:athena:workgroup", fetchAthenaExportNotebookExt)
}

// fetchAthenaGetQueryExecutionExt implements the exposure probe for
// aws-athena-query-string-config (GetQueryExecution -> QueryExecution.Query).
//
// GetQueryExecution requires a QueryExecutionId not present in the workgroup
// inventory item. We enumerate execution IDs via ListQueryExecutions(WorkGroup)
// and call GetQueryExecution for each, returning all as a slice.
func fetchAthenaGetQueryExecutionExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	workgroup := itemStr(item, "native_id", "name")
	svc := athena.NewFromConfig(c.cfg)
	optFn := func(o *athena.Options) { o.Region = region }

	var ids []string
	var nextToken *string
	for {
		listOut, err := svc.ListQueryExecutions(ctx, &athena.ListQueryExecutionsInput{
			WorkGroup: aws.String(workgroup),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListQueryExecutions: %w", err)
		}
		ids = append(ids, listOut.QueryExecutionIds...)
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	var results []any
	for _, id := range ids {
		id := id
		out, err := svc.GetQueryExecution(ctx, &athena.GetQueryExecutionInput{
			QueryExecutionId: aws.String(id),
		}, optFn)
		if err != nil {
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}

// fetchAthenaGetQueryResultsExt implements the exposure probe for
// aws-athena-query-result-rows (GetQueryResults -> ResultSet.Rows[].Data[].VarCharValue).
//
// GetQueryResults requires a QueryExecutionId. We enumerate via ListQueryExecutions
// scoped to the workgroup and fetch the first page of results for each execution.
func fetchAthenaGetQueryResultsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	workgroup := itemStr(item, "native_id", "name")
	svc := athena.NewFromConfig(c.cfg)
	optFn := func(o *athena.Options) { o.Region = region }

	var ids []string
	var nextToken *string
	for {
		listOut, err := svc.ListQueryExecutions(ctx, &athena.ListQueryExecutionsInput{
			WorkGroup: aws.String(workgroup),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListQueryExecutions: %w", err)
		}
		ids = append(ids, listOut.QueryExecutionIds...)
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	var results []any
	for _, id := range ids {
		id := id
		out, err := svc.GetQueryResults(ctx, &athena.GetQueryResultsInput{
			QueryExecutionId: aws.String(id),
		}, optFn)
		if err != nil {
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}

// fetchAthenaGetNamedQueryExt implements the exposure probe for
// aws-athena-named-query-string (GetNamedQuery -> NamedQuery.QueryString).
//
// GetNamedQuery requires a NamedQueryId. We enumerate IDs via
// ListNamedQueries(WorkGroup) and call GetNamedQuery for each.
func fetchAthenaGetNamedQueryExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	workgroup := itemStr(item, "native_id", "name")
	svc := athena.NewFromConfig(c.cfg)
	optFn := func(o *athena.Options) { o.Region = region }

	var ids []string
	var nextToken *string
	for {
		listOut, err := svc.ListNamedQueries(ctx, &athena.ListNamedQueriesInput{
			WorkGroup: aws.String(workgroup),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListNamedQueries: %w", err)
		}
		ids = append(ids, listOut.NamedQueryIds...)
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	var results []any
	for _, id := range ids {
		id := id
		out, err := svc.GetNamedQuery(ctx, &athena.GetNamedQueryInput{
			NamedQueryId: aws.String(id),
		}, optFn)
		if err != nil {
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}

// fetchAthenaGetPreparedStatementExt implements the exposure probe for
// aws-athena-prepared-statement-query (GetPreparedStatement -> PreparedStatement.QueryStatement).
//
// GetPreparedStatement requires a StatementName and WorkGroup. We enumerate
// statement names via ListPreparedStatements(WorkGroup) and call GetPreparedStatement
// for each, using the same workgroup as both the list scope and the fetch parameter.
func fetchAthenaGetPreparedStatementExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	workgroup := itemStr(item, "native_id", "name")
	svc := athena.NewFromConfig(c.cfg)
	optFn := func(o *athena.Options) { o.Region = region }

	var stmtNames []string
	var nextToken *string
	for {
		listOut, err := svc.ListPreparedStatements(ctx, &athena.ListPreparedStatementsInput{
			WorkGroup: aws.String(workgroup),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListPreparedStatements: %w", err)
		}
		for _, s := range listOut.PreparedStatements {
			if s.StatementName != nil {
				stmtNames = append(stmtNames, *s.StatementName)
			}
		}
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	var results []any
	for _, name := range stmtNames {
		name := name
		out, err := svc.GetPreparedStatement(ctx, &athena.GetPreparedStatementInput{
			StatementName: aws.String(name),
			WorkGroup:     aws.String(workgroup),
		}, optFn)
		if err != nil {
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}

// fetchAthenaExportNotebookExt implements the exposure probe for
// aws-athena-notebook-cell-content (ExportNotebook -> Payload).
//
// ExportNotebook requires a NotebookId not present in the workgroup inventory item.
// We enumerate notebook IDs via ListNotebookMetadata(WorkGroup) and call
// ExportNotebook for each.
func fetchAthenaExportNotebookExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	workgroup := itemStr(item, "native_id", "name")
	svc := athena.NewFromConfig(c.cfg)
	optFn := func(o *athena.Options) { o.Region = region }

	var notebookIDs []string
	var nextToken *string
	for {
		listOut, err := svc.ListNotebookMetadata(ctx, &athena.ListNotebookMetadataInput{
			WorkGroup: aws.String(workgroup),
			NextToken: nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListNotebookMetadata: %w", err)
		}
		for _, nb := range listOut.NotebookMetadataList {
			if nb.NotebookId != nil {
				notebookIDs = append(notebookIDs, *nb.NotebookId)
			}
		}
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	var results []any
	for _, id := range notebookIDs {
		id := id
		out, err := svc.ExportNotebook(ctx, &athena.ExportNotebookInput{
			NotebookId: aws.String(id),
		}, optFn)
		if err != nil {
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}
