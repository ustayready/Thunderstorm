package aws

// Exposure probes for API Gateway REST API — additional read_api operations.
// The only inventory resource type is aws:apigateway:rest-api whose native_id
// is the restApiId string.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func init() {
	registerFetcher("GetStage", "aws:apigateway:rest-api", fetchAPIGatewayGetStageExt)
}

// fetchAPIGatewayGetStageExt implements the exposure probe
// aws-apigateway-rest-stage-variables (GetStage -> variables.<value>).
//
// Because the inventory item is a REST API (not an individual stage), we first
// enumerate all stages for the API via GetStages and then call GetStage for
// each one.  All stage-variable maps are merged into a single top-level
// "variables" map so the catalog response_path "variables.<value>" resolves
// correctly against the aggregated result.
func fetchAPIGatewayGetStageExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := apigateway.NewFromConfig(c.cfg)
	ro := func(o *apigateway.Options) { o.Region = region }

	restAPIID := itemStr(item, "native_id", "arn")

	// Enumerate all stages for this REST API.
	stagesOut, err := svc.GetStages(ctx, &apigateway.GetStagesInput{
		RestApiId: aws.String(restAPIID),
	}, ro)
	if err != nil {
		return nil, fmt.Errorf("GetStages(%s): %w", restAPIID, err)
	}

	// Merge stage variables from every stage into a single flat map so the
	// catalog path "variables.<value>" can extract them all in one pass.
	merged := map[string]string{}
	for _, s := range stagesOut.Item {
		stageName := aws.ToString(s.StageName)
		stageOut, err := svc.GetStage(ctx, &apigateway.GetStageInput{
			RestApiId: aws.String(restAPIID),
			StageName: aws.String(stageName),
		}, ro)
		if err != nil {
			// A per-stage error is non-fatal — skip missing/deleted stages.
			continue
		}
		for k, v := range stageOut.Variables {
			// Namespace colliding keys by stage name so no value is silently
			// overwritten when two stages share a variable name.
			key := stageName + "." + k
			merged[key] = v
		}
	}

	return map[string]any{"variables": merged}, nil
}
