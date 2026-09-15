package aws

// Exposure probes for Elastic Beanstalk — remaining read_api operations.
//
// Covered here:
//   - DescribeConfigurationSettings (environment variant)
//     → aws-beanstalk-application-environment-option-value
//   - DescribeConfigurationSettings (saved-template variant)
//     → aws-beanstalk-saved-configuration-option-value
//
// Both YAML sites map to the same operation name, so a single fetcher
// handles both: it calls DescribeConfigurationSettings for the environment
// (keyed by EnvironmentName = native_id) and, in the same pass, enumerates
// all saved configuration templates associated with the same application and
// calls DescribeConfigurationSettings for each one. All results are merged
// into a single ConfigurationSettings slice so the catalog response_path
// resolves correctly against the aggregated output.
//
// The ApplicationName required by DescribeConfigurationSettings is obtained by
// a preliminary DescribeEnvironments call filtered to the known EnvironmentId
// (EnvironmentNames filter). This is a single extra call per environment item.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
)

func init() {
	registerFetcher("DescribeConfigurationSettings", "aws:beanstalk:environment", fetchBeanstalkDescribeConfigurationSettingsExt)
}

// fetchBeanstalkDescribeConfigurationSettingsExt implements the exposure probes:
//   - aws-beanstalk-application-environment-option-value
//   - aws-beanstalk-saved-configuration-option-value
//
// It first resolves the ApplicationName for the environment item, then fetches
// configuration settings for (a) the environment itself and (b) every saved
// configuration template attached to that application. The combined
// ConfigurationSettings slice is returned so both catalog response_paths resolve.
func fetchBeanstalkDescribeConfigurationSettingsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	environmentName := itemStr(item, "native_id")
	if environmentName == "" {
		return nil, fmt.Errorf("beanstalk: DescribeConfigurationSettings: native_id (environment_name) is empty")
	}

	svc := elasticbeanstalk.NewFromConfig(c.cfg)
	opt := func(o *elasticbeanstalk.Options) { o.Region = region }

	// Step 1: Resolve the ApplicationName for this environment.
	envOut, err := svc.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
		EnvironmentNames: []string{environmentName},
	}, opt)
	if err != nil {
		return nil, fmt.Errorf("beanstalk: DescribeEnvironments(%s): %w", environmentName, err)
	}
	if len(envOut.Environments) == 0 {
		return nil, fmt.Errorf("beanstalk: environment %q not found", environmentName)
	}

	applicationName := aws.ToString(envOut.Environments[0].ApplicationName)
	if applicationName == "" {
		return nil, fmt.Errorf("beanstalk: ApplicationName empty for environment %q", environmentName)
	}

	// Step 2: Fetch configuration settings for the environment itself.
	envCfgOut, err := svc.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		ApplicationName: aws.String(applicationName),
		EnvironmentName: aws.String(environmentName),
	}, opt)
	if err != nil {
		return nil, fmt.Errorf("beanstalk: DescribeConfigurationSettings(env=%s): %w", environmentName, err)
	}

	// Start accumulating all ConfigurationSettingsDescription objects.
	allSettings := make([]any, 0, len(envCfgOut.ConfigurationSettings))
	for _, s := range envCfgOut.ConfigurationSettings {
		allSettings = append(allSettings, jsonify(s))
	}

	// Step 3: Enumerate saved configuration templates for this application and
	// fetch configuration settings for each template.
	appOut, err := svc.DescribeApplications(ctx, &elasticbeanstalk.DescribeApplicationsInput{
		ApplicationNames: []string{applicationName},
	}, opt)
	if err == nil && len(appOut.Applications) > 0 {
		for _, templateName := range appOut.Applications[0].ConfigurationTemplates {
			if templateName == "" {
				continue
			}
			tmplCfgOut, tmplErr := svc.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
				ApplicationName: aws.String(applicationName),
				TemplateName:    aws.String(templateName),
			}, opt)
			if tmplErr != nil {
				// A template may be deleted between enumeration and fetch; skip it.
				continue
			}
			for _, s := range tmplCfgOut.ConfigurationSettings {
				allSettings = append(allSettings, jsonify(s))
			}
		}
	}
	// A failure to list templates is non-fatal; the environment settings were
	// already collected above.

	return map[string]any{"ConfigurationSettings": allSettings}, nil
}
