package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
)

func init() {
	registerListFetcher("GetDataCellsFilter", listFetchLakeformationGetDataCellsFilter)
}

// listFetchLakeformationGetDataCellsFilter enumerates all data cells filters
// across the region via ListDataCellsFilter (no table filter = all filters),
// then fetches full detail for each via GetDataCellsFilter (read-only);
// per-item errors are skipped.
func listFetchLakeformationGetDataCellsFilter(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := lakeformation.NewFromConfig(c.cfg)
	ro := func(o *lakeformation.Options) { o.Region = region }
	var out []any

	p := lakeformation.NewListDataCellsFilterPaginator(svc, &lakeformation.ListDataCellsFilterInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, f := range page.DataCellsFilters {
			if f.TableCatalogId == nil || f.DatabaseName == nil || f.TableName == nil || f.Name == nil {
				continue
			}
			d, e := svc.GetDataCellsFilter(ctx, &lakeformation.GetDataCellsFilterInput{
				TableCatalogId: f.TableCatalogId,
				DatabaseName:   f.DatabaseName,
				TableName:      f.TableName,
				Name:           f.Name,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}
