package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
)

// Record is one result item from an operation, with flat keys the registry
// manifest references (id_field / attributes / yields / capture).
type Record = map[string]any

// OpFunc implements a single registry operation. region is "" for global ops.
type OpFunc func(ctx context.Context, c *Client, region string, params map[string]string) ([]Record, error)

// BlobDir, if set, is where http:GetBlob stores downloaded artifacts.
func (c *Client) SetBlobDir(dir string) { c.blobDir = dir }

// Invoke dispatches a registry operation by name. Unknown ops are a hard error
// (a manifest referencing an unimplemented op must fail loudly, not silently).
func (c *Client) Invoke(ctx context.Context, op, region string, params map[string]string) ([]Record, error) {
	fn, ok := operations[op]
	if !ok {
		return nil, fmt.Errorf("no implementation for operation %q", op)
	}
	return fn(ctx, c, region, params)
}

// HasOp reports whether an operation is implemented (used to validate manifests).
func HasOp(op string) bool { _, ok := operations[op]; return ok }

// register adds an operation to the dispatch map. Per-service files call this
// from their init() so breadth can be added without editing this file (avoids
// conflicts when many services are authored in parallel).
func register(name string, fn OpFunc) { operations[name] = fn }

var operations = map[string]OpFunc{
	"iam:ListUsers":              opIAMListUsers,
	"s3:ListBuckets":             opS3ListBuckets,
	"lambda:ListFunctions":       opLambdaListFunctions,
	"lambda:GetFunction":         opLambdaGetFunction,
	"codebuild:ListProjects":     opCodeBuildListProjects,
	"codebuild:BatchGetProjects": opCodeBuildBatchGet,
	"secretsmanager:ListSecrets": opSMListSecrets,
	"http:GetBlob":               opHTTPGetBlob,
}

func opSMListSecrets(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := secretsmanager.NewFromConfig(c.cfg)
	p := secretsmanager.NewListSecretsPaginator(svc, &secretsmanager.ListSecretsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *secretsmanager.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, s := range out.SecretList {
			recs = append(recs, Record{
				"secret_name": aws.ToString(s.Name),
				"arn":         aws.ToString(s.ARN),
			})
		}
	}
	return recs, nil
}

// GetSecretValue is the EXPOSURE PROBE for aws-secretsmanager-secret-value-*.
// Read-only; returns the plaintext SecretString for detection+redaction.
func (c *Client) GetSecretValue(ctx context.Context, region, secretID string) (string, error) {
	out, err := secretsmanager.NewFromConfig(c.cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}, func(o *secretsmanager.Options) { o.Region = region })
	if err != nil {
		return "", err
	}
	return aws.ToString(out.SecretString), nil
}

func opIAMListUsers(ctx context.Context, c *Client, _ string, _ map[string]string) ([]Record, error) {
	out, err := iam.NewFromConfig(c.cfg).ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	recs := make([]Record, 0, len(out.Users))
	for _, u := range out.Users {
		recs = append(recs, Record{
			"user_name": aws.ToString(u.UserName),
			"user_id":   aws.ToString(u.UserId),
			"arn":       aws.ToString(u.Arn),
		})
	}
	return recs, nil
}

func opS3ListBuckets(ctx context.Context, c *Client, _ string, _ map[string]string) ([]Record, error) {
	out, err := s3.NewFromConfig(c.cfg).ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	recs := make([]Record, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		recs = append(recs, Record{
			"bucket_name": name,
			"arn":         "arn:aws:s3:::" + name,
		})
	}
	return recs, nil
}

func opLambdaListFunctions(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := lambda.NewFromConfig(c.cfg)
	p := lambda.NewListFunctionsPaginator(svc, &lambda.ListFunctionsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *lambda.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, f := range out.Functions {
			recs = append(recs, Record{
				"function_name": aws.ToString(f.FunctionName),
				"function_arn":  aws.ToString(f.FunctionArn),
				"role_arn":      aws.ToString(f.Role),
				"runtime":       string(f.Runtime),
			})
		}
	}
	return recs, nil
}

func opLambdaGetFunction(ctx context.Context, c *Client, region string, params map[string]string) ([]Record, error) {
	out, err := lambda.NewFromConfig(c.cfg).GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(params["FunctionName"]),
	}, func(o *lambda.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	rec := Record{}
	if out.Code != nil {
		rec["code_location"] = aws.ToString(out.Code.Location)
	}
	if out.Configuration != nil {
		rec["code_sha256"] = aws.ToString(out.Configuration.CodeSha256)
	}
	return []Record{rec}, nil
}

func opCodeBuildListProjects(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := codebuild.NewFromConfig(c.cfg)
	p := codebuild.NewListProjectsPaginator(svc, &codebuild.ListProjectsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *codebuild.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, name := range out.Projects {
			recs = append(recs, Record{"project_name": name})
		}
	}
	return recs, nil
}

func opCodeBuildBatchGet(ctx context.Context, c *Client, region string, params map[string]string) ([]Record, error) {
	// M1: one name per call (proves the binding). Batching for speed is a
	// documented follow-up.
	out, err := codebuild.NewFromConfig(c.cfg).BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
		Names: []string{params["name"]},
	}, func(o *codebuild.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	var recs []Record
	for _, pr := range out.Projects {
		rec := Record{"project_name": aws.ToString(pr.Name)}
		if pr.ServiceRole != nil {
			rec["service_role"] = aws.ToString(pr.ServiceRole)
		}
		if pr.Source != nil {
			rec["source_type"] = string(pr.Source.Type)
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// opHTTPGetBlob downloads a URL (e.g. a Lambda code presigned URL), stores it in
// the blob dir by content hash, and returns size + sha. Read-only fetch.
func opHTTPGetBlob(ctx context.Context, c *Client, _ string, params map[string]string) ([]Record, error) {
	url := params["url"]
	if url == "" {
		return nil, errors.New("http:GetBlob: empty url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	var size int64
	var sink io.Writer = h
	var tmp *os.File
	if c.blobDir != "" {
		if err := os.MkdirAll(c.blobDir, 0o755); err != nil {
			return nil, err
		}
		tmp, err = os.CreateTemp(c.blobDir, "blob-*")
		if err != nil {
			return nil, err
		}
		sink = io.MultiWriter(h, tmp)
	}
	if size, err = io.Copy(sink, resp.Body); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if tmp != nil {
		tmp.Close()
		_ = os.Rename(tmp.Name(), filepath.Join(c.blobDir, sum))
	}
	return []Record{{"code_size": size, "code_blob_sha": sum, "evidence_ref": "blob://" + sum}}, nil
}

// Classify maps an SDK error to a coarse outcome hint: "denied", "throttled",
// or "error". This drives the ledger's expected-gap vs retryable distinction.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		switch {
		case strings.Contains(code, "AccessDenied"), strings.Contains(code, "Unauthorized"),
			strings.Contains(code, "Forbidden"):
			return "denied"
		case strings.Contains(code, "Throttl"), strings.Contains(code, "TooManyRequests"),
			strings.Contains(code, "RequestLimitExceeded"):
			return "throttled"
		}
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "AccessDenied"), strings.Contains(s, "not authorized"),
		strings.Contains(s, "UnauthorizedOperation"):
		return "denied"
	case strings.Contains(s, "Throttl"), strings.Contains(s, "RequestLimitExceeded"):
		return "throttled"
	}
	return "error"
}
