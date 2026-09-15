package aws

// Self-enumerating exposure fetchers for AWS API Gateway (REST) — read_api
// operations whose targets are not held in the Thunderstorm inventory.
//
// Implemented ops
//   - GetApiKey  (site aws-apigateway-rest-api-key-value)
//   - GetIntegration  (site aws-apigateway-integration-mapping-templates)
//
// Skipped
//   - GetStage (REST)      — already registered by probe_apigateway_ext.go
//   - GetTags              — already registered by probe_apigateway.go
//   - GetStage (v2)        — apigatewayv2 package absent from go.mod

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func init() {
	registerListFetcher("GetApiKey", listFetchApigatewayGetApiKey)
	registerListFetcher("GetIntegration", listFetchApigatewayGetIntegration)
}

// listFetchApigatewayGetApiKey enumerates all API keys in a region and returns
// each GetApiKey response with IncludeValue=true so the prober can extract the
// plaintext key value (response_path: value).
func listFetchApigatewayGetApiKey(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := apigateway.NewFromConfig(c.cfg)
	ro := func(o *apigateway.Options) { o.Region = region }

	var out []any
	p := apigateway.NewGetApiKeysPaginator(svc, &apigateway.GetApiKeysInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, key := range page.Items {
			if key.Id == nil {
				continue
			}
			d, e := svc.GetApiKey(ctx, &apigateway.GetApiKeyInput{
				ApiKey:       key.Id,
				IncludeValue: aws.Bool(true),
			}, ro)
			if e != nil {
				continue // access denied or key deleted — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchApigatewayGetIntegration enumerates all REST APIs → resources
// (with embedded method metadata) → HTTP methods and returns each GetIntegration
// response so the prober can extract requestTemplates, requestParameters, and
// uri (response_path: requestTemplates / requestParameters / uri).
func listFetchApigatewayGetIntegration(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := apigateway.NewFromConfig(c.cfg)
	ro := func(o *apigateway.Options) { o.Region = region }

	var out []any

	// Enumerate REST APIs.
	apiPager := apigateway.NewGetRestApisPaginator(svc, &apigateway.GetRestApisInput{})
	for apiPager.HasMorePages() {
		apiPage, err := apiPager.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, api := range apiPage.Items {
			if api.Id == nil {
				continue
			}
			restAPIID := api.Id

			// Enumerate resources for this REST API, embedding method metadata so
			// we can read ResourceMethods without an extra API call per resource.
			resPager := apigateway.NewGetResourcesPaginator(svc, &apigateway.GetResourcesInput{
				RestApiId: restAPIID,
				Embed:     []string{"methods"},
			})
			for resPager.HasMorePages() {
				resPage, err := resPager.NextPage(ctx, ro)
				if err != nil {
					break // non-fatal: skip resources for this API
				}
				for _, res := range resPage.Items {
					if res.Id == nil {
						continue
					}
					for httpMethod := range res.ResourceMethods {
						d, e := svc.GetIntegration(ctx, &apigateway.GetIntegrationInput{
							RestApiId:  restAPIID,
							ResourceId: res.Id,
							HttpMethod: aws.String(httpMethod),
						}, ro)
						if e != nil {
							continue // method has no integration or access denied
						}
						out = append(out, jsonify(d))
					}
				}
			}
		}
	}
	return out, nil
}
