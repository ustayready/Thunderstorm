// Package exposure loads the credential-exposure catalogs and probes read_api
// sites for real secrets. Non-read_api sites are recorded as known surfaces and
// NEVER invoked — a safety gate enforced structurally.
package exposure

import (
	"encoding/json"
	"sort"
	"strings"

	assets "thunderstorm/collector"
)

// Read is a site's collection recipe.
type Read struct {
	AccessMode   string         `json:"access_mode"`
	Operation    string         `json:"operation"`
	Params       map[string]any `json:"params"`
	ResponsePath string         `json:"response_path"`
	Encoding     string         `json:"encoding"`
}

// Site is one credential-exposure location (from RAGE exposure-db).
type Site struct {
	ID                  string   `json:"id"`
	Service             string   `json:"-"` // filled from the exposure-db service key
	Location            string   `json:"location"`
	LocationKind        string   `json:"location_kind"`
	DataKinds           []string `json:"data_kinds"`
	Read                Read     `json:"read"`
	RequiredPermissions []string `json:"required_permissions"`
	EmitsHint           string   `json:"emits"` // RAGE edge this exposure emits
	Severity            string   `json:"severity"`
}

// IsReadAPI reports whether this site may be actively invoked. Only read_api
// sites are ever called; every other access_mode is a recorded surface.
func (s Site) IsReadAPI() bool { return s.Read.AccessMode == "read_api" }

// rageExposureFile is the shape of RAGE exposure-db/<provider>.json.
type rageExposureFile struct {
	Provider string `json:"provider"`
	Services map[string]struct {
		Name  string `json:"name"`
		Sites []Site `json:"sites"`
	} `json:"services"`
}

// LoadCatalog reads the credential-exposure catalogs from RAGE's exposure-db/<provider>.json into a
// flat, stably-sorted site list. Live from the RAGE checkout when present, else the embedded snapshot.
func LoadCatalog(provider string) ([]Site, error) {
	b, err := assets.ReadRAGE("exposure-db/" + provider + ".json")
	if err != nil {
		return nil, err
	}
	var ef rageExposureFile
	if err := json.Unmarshal(b, &ef); err != nil {
		return nil, err
	}
	var sites []Site
	for key, svc := range ef.Services {
		bare := key
		if i := strings.IndexByte(key, ':'); i >= 0 {
			bare = key[i+1:] // "aws:accessanalyzer" -> "accessanalyzer"
		}
		for _, s := range svc.Sites {
			s.Service = bare
			sites = append(sites, s)
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].ID < sites[j].ID })
	return sites, nil
}
