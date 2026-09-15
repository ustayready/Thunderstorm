// Package registry loads the declarative Resource Registry — the backbone that
// says how to enumerate each resource, what IDs it yields, and how detail calls
// bind to those IDs. It is provider-agnostic; provider adapters supply the
// operation implementations by name.
package registry

import (
	"encoding/json"
	"fmt"
	"sort"

	assets "thunderstorm/collector"
)

// Field extracts a named value from an operation's result record.
type Field = string

// Enumerate is the "list/describe" call that discovers resources.
type Enumerate struct {
	Operation  string  `yaml:"operation" json:"operation"`   // e.g. lambda:ListFunctions
	IDField    string  `yaml:"id_field" json:"id_field"`     // record key → Artifact.NativeID
	ARNField   string  `yaml:"arn_field" json:"arn_field"`   // record key → Artifact.ARN (optional)
	Attributes []Field `yaml:"attributes" json:"attributes"` // record keys → Artifact.Attributes
	Yields     []Field `yaml:"yields" json:"yields"`         // record keys carried forward for bindings
}

// Detail is a per-item enrichment call, bound to fields yielded upstream.
type Detail struct {
	Operation string            `yaml:"operation" json:"operation"`
	Bind      map[string]string `yaml:"bind" json:"bind"`       // param → $var (resolved from the record)
	Capture   []Field           `yaml:"capture" json:"capture"` // record keys merged back into the record/artifact
}

// ResourceType is one enumerable resource + its dependency chain.
type ResourceType struct {
	ResourceType        string    `yaml:"resource_type" json:"-"`     // the RAGE resources{} map KEY, e.g. aws:lambda:function
	NodeType            string    `yaml:"node_type" json:"node_type"` // → RAGE vocab/node-types.json
	Scope               string    `yaml:"scope" json:"scope"`         // global | regional
	Enumerate           Enumerate `yaml:"enumerate" json:"enumerate"`
	Detail              []Detail  `yaml:"detail" json:"detail"`
	RequiredPermissions []string  `yaml:"required_permissions" json:"required_permissions"`
}

// Registry is the loaded set of resource types for a provider.
type Registry struct {
	Provider  string
	Resources []ResourceType
}

// rageProviderFile is the shape of RAGE providers/<provider>.json: resources keyed by resource_type.
type rageProviderFile struct {
	Provider  string                  `json:"provider"`
	Resources map[string]ResourceType `json:"resources"`
}

// Load reads the collection recipes for a provider from RAGE's providers/<provider>.json — the
// source of truth for what to enumerate and how detail calls bind. Live from the RAGE checkout
// when $RAGE_ROOT is set, else the snapshot embedded in the binary.
func Load(provider string) (*Registry, error) {
	b, err := assets.ReadRAGE("providers/" + provider + ".json")
	if err != nil {
		return nil, fmt.Errorf("reading RAGE registry for %s: %w", provider, err)
	}
	var pf rageProviderFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return nil, fmt.Errorf("parsing RAGE providers/%s.json: %w", provider, err)
	}
	reg := &Registry{Provider: provider}
	for rt, res := range pf.Resources {
		res.ResourceType = rt // the map key IS the resource_type
		reg.Resources = append(reg.Resources, res)
	}
	sort.Slice(reg.Resources, func(i, j int) bool {
		return reg.Resources[i].ResourceType < reg.Resources[j].ResourceType
	})
	return reg, nil
}

// RequiredPermissions returns the union of permissions across all resource
// types — used by the M2 preflight.
func (r *Registry) RequiredPermissions() []string {
	set := map[string]struct{}{}
	for _, rt := range r.Resources {
		for _, p := range rt.RequiredPermissions {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
