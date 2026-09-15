module thunderstorm/collector

go 1.26.2

require (
	github.com/aws/aws-sdk-go-v2 v1.46.0
	github.com/aws/aws-sdk-go-v2/config v1.33.3
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.55.0
	github.com/aws/aws-sdk-go-v2/service/account v1.40.0
	github.com/aws/aws-sdk-go-v2/service/acm v1.49.0
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.55.0
	github.com/aws/aws-sdk-go-v2/service/amplify v1.47.0
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.46.0
	github.com/aws/aws-sdk-go-v2/service/appflow v1.59.0
	github.com/aws/aws-sdk-go-v2/service/appmesh v1.43.0
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.47.0
	github.com/aws/aws-sdk-go-v2/service/athena v1.65.0
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.77.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.64.0
	github.com/aws/aws-sdk-go-v2/service/batch v1.74.0
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.71.0
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.80.0
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.72.0
	github.com/aws/aws-sdk-go-v2/service/cloudhsmv2 v1.42.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.63.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.71.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.86.0
	github.com/aws/aws-sdk-go-v2/service/codeartifact v1.45.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.77.0
	github.com/aws/aws-sdk-go-v2/service/codecommit v1.42.0
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.43.0
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.54.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.73.0
	github.com/aws/aws-sdk-go-v2/service/configservice v1.73.0
	github.com/aws/aws-sdk-go-v2/service/controltower v1.36.0
	github.com/aws/aws-sdk-go-v2/service/datapipeline v1.37.0
	github.com/aws/aws-sdk-go-v2/service/detective v1.46.0
	github.com/aws/aws-sdk-go-v2/service/directconnect v1.49.0
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.46.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.67.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.329.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.64.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.96.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.48.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.98.0
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.60.0
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.41.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.62.0
	github.com/aws/aws-sdk-go-v2/service/emr v1.69.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.53.0
	github.com/aws/aws-sdk-go-v2/service/fms v1.52.0
	github.com/aws/aws-sdk-go-v2/service/fsx v1.73.0
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.43.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.157.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.91.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.63.0
	github.com/aws/aws-sdk-go-v2/service/imagebuilder v1.62.0
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.58.0
	github.com/aws/aws-sdk-go-v2/service/kafka v1.63.0
	github.com/aws/aws-sdk-go-v2/service/keyspaces v1.32.0
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.53.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.59.0
	github.com/aws/aws-sdk-go-v2/service/lakeformation v1.54.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.107.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.64.0
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.58.0
	github.com/aws/aws-sdk-go-v2/service/memorydb v1.41.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.43.0
	github.com/aws/aws-sdk-go-v2/service/neptune v1.52.0
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.71.0
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.49.0
	github.com/aws/aws-sdk-go-v2/service/opsworks v1.31.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.59.0
	github.com/aws/aws-sdk-go-v2/service/qldb v1.32.2
	github.com/aws/aws-sdk-go-v2/service/quicksight v1.129.0
	github.com/aws/aws-sdk-go-v2/service/ram v1.43.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.128.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.70.0
	github.com/aws/aws-sdk-go-v2/service/rolesanywhere v1.30.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.69.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.111.0
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.274.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.48.0
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.80.0
	github.com/aws/aws-sdk-go-v2/service/servicecatalog v1.46.0
	github.com/aws/aws-sdk-go-v2/service/sfn v1.49.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.46.0
	github.com/aws/aws-sdk-go-v2/service/sqs v1.51.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.77.0
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.47.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.49.0
	github.com/aws/aws-sdk-go-v2/service/timestreamwrite v1.42.0
	github.com/aws/aws-sdk-go-v2/service/vpclattice v1.31.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.82.0
	github.com/aws/smithy-go v1.28.1
	gopkg.in/yaml.v3 v3.0.1
	thunderstorm/engine v0.0.0
)

// The engine is a sibling module (pure stdlib, no external deps) — pulled in so
// the combined `thunderstorm` binary builds the graph in-process, one binary.
replace thunderstorm/engine => ../engine

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.23.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.12.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.9.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.37.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.42.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
