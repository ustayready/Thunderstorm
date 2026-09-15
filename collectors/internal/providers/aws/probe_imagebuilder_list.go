package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/imagebuilder"
)

func init() {
	registerListFetcher("GetComponent", listFetchImagebuilderGetComponent)
	registerListFetcher("GetImageRecipe", listFetchImagebuilderGetImageRecipe)
	registerListFetcher("GetContainerRecipe", listFetchImagebuilderGetContainerRecipe)
	registerListFetcher("GetWorkflow", listFetchImagebuilderGetWorkflow)
}

// listFetchImagebuilderGetComponent enumerates all component versions in the
// region, then all build versions per component version, and fetches the full
// component document for each via GetComponent (read-only); per-item errors are
// skipped. The prober applies the site's response_path (component.data) to each
// returned result.
func listFetchImagebuilderGetComponent(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := imagebuilder.NewFromConfig(c.cfg)
	ro := func(o *imagebuilder.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate component semantic versions.
	vp := imagebuilder.NewListComponentsPaginator(svc, &imagebuilder.ListComponentsInput{})
	for vp.HasMorePages() {
		vPage, err := vp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, cv := range vPage.ComponentVersionList {
			if cv.Arn == nil {
				continue
			}

			// Step 2: enumerate build versions for this component version.
			bp := imagebuilder.NewListComponentBuildVersionsPaginator(svc, &imagebuilder.ListComponentBuildVersionsInput{
				ComponentVersionArn: cv.Arn,
			})
			for bp.HasMorePages() {
				bPage, err := bp.NextPage(ctx, ro)
				if err != nil {
					break // move to next component version on error
				}
				for _, cs := range bPage.ComponentSummaryList {
					if cs.Arn == nil {
						continue
					}
					// Step 3: fetch full component detail (includes the data field).
					d, e := svc.GetComponent(ctx, &imagebuilder.GetComponentInput{
						ComponentBuildVersionArn: cs.Arn,
					}, ro)
					if e != nil {
						continue // per-item error (not found / access) — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}

// listFetchImagebuilderGetImageRecipe enumerates all image recipes in the
// region and fetches the full recipe detail for each via GetImageRecipe
// (read-only); per-item errors are skipped. The prober applies the site's
// response_path to each returned result.
func listFetchImagebuilderGetImageRecipe(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := imagebuilder.NewFromConfig(c.cfg)
	ro := func(o *imagebuilder.Options) { o.Region = region }
	var out []any

	p := imagebuilder.NewListImageRecipesPaginator(svc, &imagebuilder.ListImageRecipesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, rs := range page.ImageRecipeSummaryList {
			if rs.Arn == nil {
				continue
			}
			d, e := svc.GetImageRecipe(ctx, &imagebuilder.GetImageRecipeInput{
				ImageRecipeArn: rs.Arn,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchImagebuilderGetContainerRecipe enumerates all container recipes in
// the region and fetches the full recipe detail for each via GetContainerRecipe
// (read-only); per-item errors are skipped. The prober applies the site's
// response_path (containerRecipe.dockerfileTemplateData) to each returned result.
func listFetchImagebuilderGetContainerRecipe(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := imagebuilder.NewFromConfig(c.cfg)
	ro := func(o *imagebuilder.Options) { o.Region = region }
	var out []any

	p := imagebuilder.NewListContainerRecipesPaginator(svc, &imagebuilder.ListContainerRecipesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, rs := range page.ContainerRecipeSummaryList {
			if rs.Arn == nil {
				continue
			}
			d, e := svc.GetContainerRecipe(ctx, &imagebuilder.GetContainerRecipeInput{
				ContainerRecipeArn: rs.Arn,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchImagebuilderGetWorkflow enumerates all workflow versions in the
// region, then all build versions per workflow version, and fetches the full
// workflow document for each via GetWorkflow (read-only); per-item errors are
// skipped. The prober applies the site's response_path (workflow.data) to each
// returned result.
func listFetchImagebuilderGetWorkflow(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := imagebuilder.NewFromConfig(c.cfg)
	ro := func(o *imagebuilder.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate workflow semantic versions.
	vp := imagebuilder.NewListWorkflowsPaginator(svc, &imagebuilder.ListWorkflowsInput{})
	for vp.HasMorePages() {
		vPage, err := vp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, wv := range vPage.WorkflowVersionList {
			if wv.Arn == nil {
				continue
			}

			// Step 2: enumerate build versions for this workflow version.
			bp := imagebuilder.NewListWorkflowBuildVersionsPaginator(svc, &imagebuilder.ListWorkflowBuildVersionsInput{
				WorkflowVersionArn: wv.Arn,
			})
			for bp.HasMorePages() {
				bPage, err := bp.NextPage(ctx, ro)
				if err != nil {
					break // move to next workflow version on error
				}
				for _, ws := range bPage.WorkflowSummaryList {
					if ws.Arn == nil {
						continue
					}
					// Step 3: fetch full workflow detail (includes the data field).
					d, e := svc.GetWorkflow(ctx, &imagebuilder.GetWorkflowInput{
						WorkflowBuildVersionArn: ws.Arn,
					}, ro)
					if e != nil {
						continue // per-item error (not found / access) — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}
