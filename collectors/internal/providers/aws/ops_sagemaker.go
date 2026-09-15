package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

func init() { register("sagemaker:ListNotebookInstances", opSageMakerListNotebookInstances) }

// opSageMakerListNotebookInstances enumerates SageMaker notebook instances (read-only).
func opSageMakerListNotebookInstances(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := sagemaker.NewFromConfig(c.cfg)
	p := sagemaker.NewListNotebookInstancesPaginator(svc, &sagemaker.ListNotebookInstancesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *sagemaker.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, nb := range out.NotebookInstances {
			recs = append(recs, Record{
				"notebook_instance_name": aws.ToString(nb.NotebookInstanceName),
				"arn":                    aws.ToString(nb.NotebookInstanceArn),
			})
		}
	}
	return recs, nil
}
