package azure

import (
	"context"

	"thunderstorm/collector/internal/exposure"
)

// Azure exposure has two layers:
//   1. CONTROL-PLANE (public network access, anonymous-blob toggle) — derived by the
//      engine from ARG `properties`, so no probe is needed here.
//   2. DATA-PLANE CONFIRMED LEAKS — this file: the prober actively reads real credential
//      material (storage account keys, Cosmos keys, Key Vault secret VALUES) and records
//      a redacted hit. Only these high-signal, definitionally-sensitive locations are
//      probed; each is a read_api site in RAGE exposure-db/azure.json.
// Read-only + redacted (salted hash + length + suffix); raw values never stored.

func itemARN(item map[string]any) string {
	if s, ok := item["arn"].(string); ok && s != "" {
		return s
	}
	if s, ok := item["native_id"].(string); ok {
		return s
	}
	return ""
}

// ExposureFetchers wires the data-plane credential-fetch operations.
func ExposureFetchers(c *Client) exposure.FetcherSet {
	return exposure.FetcherSet{
		// Storage account keys: listKeys returns the account keys = full data access + SAS minting.
		"azure:storage:listKeys": {
			ResourceType: "azure:storage:account",
			Fetch: func(ctx context.Context, region string, item map[string]any) (any, error) {
				return c.armPost(ctx, itemARN(item)+"/listKeys?api-version=2023-01-01")
			},
		},
		// Cosmos DB keys: listKeys returns the primary/secondary master keys.
		"azure:cosmos:listKeys": {
			ResourceType: "azure:documentdb:cosmos",
			Fetch: func(ctx context.Context, region string, item map[string]any) (any, error) {
				return c.armPost(ctx, itemARN(item)+"/listKeys?api-version=2023-04-15")
			},
		},
		// Key Vault secret VALUES (data plane): enumerate secrets, read each value.
		"azure:keyvault:secretValues": {
			ResourceType: "azure:keyvault:vault",
			Fetch: func(ctx context.Context, region string, item map[string]any) (any, error) {
				return c.keyVaultSecretValues(ctx, item)
			},
		},
	}
}

// keyVaultSecretValues enumerates a vault's secrets and reads each value (data plane),
// returning {secrets:[{id,value}]} for the prober's response_path to extract + redact.
func (c *Client) keyVaultSecretValues(ctx context.Context, item map[string]any) (any, error) {
	props, _ := item["properties"].(map[string]any)
	uri, _ := props["vaultUri"].(string)
	if uri == "" {
		return map[string]any{"secrets": []any{}}, nil
	}
	var list struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := c.vaultGet(ctx, uri+"secrets?api-version=7.4", &list); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list.Value))
	for _, s := range list.Value {
		if s.ID == "" {
			continue
		}
		var sec struct {
			Value string `json:"value"`
		}
		if err := c.vaultGet(ctx, s.ID+"?api-version=7.4", &sec); err != nil {
			continue // per-secret denial is not fatal
		}
		if sec.Value != "" {
			out = append(out, map[string]any{"id": s.ID, "value": sec.Value})
		}
	}
	return map[string]any{"secrets": out}, nil
}

// ExposureListFetchers: none for Azure (data-plane fetchers above are inventory-driven).
func ExposureListFetchers(c *Client) exposure.ListFetcherSet {
	return exposure.ListFetcherSet{}
}
