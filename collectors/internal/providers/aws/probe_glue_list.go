package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/glue/types"
)

func init() {
	registerListFetcher("GetConnection", listFetchGlueGetConnection)
	registerListFetcher("GetWorkflowRunProperties", listFetchGlueGetWorkflowRunProperties)
	registerListFetcher("GetTable", listFetchGlueGetTable)
	registerListFetcher("GetSchemaVersion", listFetchGlueGetSchemaVersion)
}

// listFetchGlueGetConnection enumerates all Glue connections in a region and
// returns each GetConnection response (HidePassword=false) so the prober can
// extract Connection.ConnectionProperties.* for exposed credentials.
func listFetchGlueGetConnection(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := glue.NewFromConfig(c.cfg)
	ro := func(o *glue.Options) { o.Region = region }
	var out []any

	p := glue.NewGetConnectionsPaginator(svc, &glue.GetConnectionsInput{
		HidePassword: false,
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, conn := range page.ConnectionList {
			if conn.Name == nil {
				continue
			}
			d, e := svc.GetConnection(ctx, &glue.GetConnectionInput{
				Name:         conn.Name,
				HidePassword: false,
			}, ro)
			if e != nil {
				continue
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchGlueGetWorkflowRunProperties enumerates all workflows, then their
// runs, and returns each GetWorkflowRunProperties response so the prober can
// extract RunProperties.* for exposed credentials.
func listFetchGlueGetWorkflowRunProperties(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := glue.NewFromConfig(c.cfg)
	ro := func(o *glue.Options) { o.Region = region }
	var out []any

	wp := glue.NewListWorkflowsPaginator(svc, &glue.ListWorkflowsInput{})
	for wp.HasMorePages() {
		wpage, err := wp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, wfName := range wpage.Workflows {
			wfName := wfName
			rp := glue.NewGetWorkflowRunsPaginator(svc, &glue.GetWorkflowRunsInput{
				Name:         aws.String(wfName),
				IncludeGraph: aws.Bool(false),
			})
			for rp.HasMorePages() {
				rpage, rerr := rp.NextPage(ctx, ro)
				if rerr != nil {
					break
				}
				for _, run := range rpage.Runs {
					if run.WorkflowRunId == nil {
						continue
					}
					d, e := svc.GetWorkflowRunProperties(ctx, &glue.GetWorkflowRunPropertiesInput{
						Name:  aws.String(wfName),
						RunId: run.WorkflowRunId,
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

// listFetchGlueGetTable enumerates all databases and tables in the Data Catalog
// and returns each GetTable response so the prober can extract
// Table.{Parameters,StorageDescriptor.Parameters,...} for exposed credentials.
func listFetchGlueGetTable(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := glue.NewFromConfig(c.cfg)
	ro := func(o *glue.Options) { o.Region = region }
	var out []any

	dp := glue.NewGetDatabasesPaginator(svc, &glue.GetDatabasesInput{})
	for dp.HasMorePages() {
		dpage, err := dp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, db := range dpage.DatabaseList {
			if db.Name == nil {
				continue
			}
			tp := glue.NewGetTablesPaginator(svc, &glue.GetTablesInput{
				DatabaseName: db.Name,
			})
			for tp.HasMorePages() {
				tpage, terr := tp.NextPage(ctx, ro)
				if terr != nil {
					break
				}
				for _, tbl := range tpage.TableList {
					if tbl.Name == nil {
						continue
					}
					d, e := svc.GetTable(ctx, &glue.GetTableInput{
						DatabaseName: db.Name,
						Name:         tbl.Name,
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

// listFetchGlueGetSchemaVersion enumerates all Schema Registry schemas and their
// versions, returning each GetSchemaVersion response so the prober can extract
// SchemaDefinition for exposed sensitive data.
func listFetchGlueGetSchemaVersion(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := glue.NewFromConfig(c.cfg)
	ro := func(o *glue.Options) { o.Region = region }
	var out []any

	sp := glue.NewListSchemasPaginator(svc, &glue.ListSchemasInput{})
	for sp.HasMorePages() {
		spage, err := sp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, schema := range spage.Schemas {
			if schema.SchemaArn == nil {
				continue
			}
			vp := glue.NewListSchemaVersionsPaginator(svc, &glue.ListSchemaVersionsInput{
				SchemaId: &types.SchemaId{SchemaArn: schema.SchemaArn},
			})
			for vp.HasMorePages() {
				vpage, verr := vp.NextPage(ctx, ro)
				if verr != nil {
					break
				}
				for _, ver := range vpage.Schemas {
					if ver.SchemaVersionId == nil {
						continue
					}
					d, e := svc.GetSchemaVersion(ctx, &glue.GetSchemaVersionInput{
						SchemaVersionId: ver.SchemaVersionId,
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
