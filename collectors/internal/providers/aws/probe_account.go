package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/account/types"
)

func init() {
	registerFetcher("GetContactInformation", "aws:account:region", fetchAccountGetContactInformation)
	registerFetcher("GetAlternateContact", "aws:account:region", fetchAccountGetAlternateContact)
}

// Exposure probe: aws-account-contact-information-pii (GetContactInformation -> ContactInformation).
// AccountId is omitted so the call targets the identity's own account (standalone context).
func fetchAccountGetContactInformation(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := account.NewFromConfig(c.cfg).GetContactInformation(ctx, &account.GetContactInformationInput{},
		func(o *account.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-account-alternate-contact-pii (GetAlternateContact -> AlternateContact).
// Queries all three contact types (BILLING, OPERATIONS, SECURITY) and returns them as a list.
// AccountId is omitted so the call targets the identity's own account (standalone context).
func fetchAccountGetAlternateContact(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	contactTypes := []types.AlternateContactType{
		types.AlternateContactTypeBilling,
		types.AlternateContactTypeOperations,
		types.AlternateContactTypeSecurity,
	}

	var results []any
	for _, ct := range contactTypes {
		out, err := account.NewFromConfig(c.cfg).GetAlternateContact(ctx, &account.GetAlternateContactInput{
			AlternateContactType: ct,
		}, func(o *account.Options) { o.Region = region })
		if err != nil {
			// A missing contact for a type is not fatal; skip it.
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}
