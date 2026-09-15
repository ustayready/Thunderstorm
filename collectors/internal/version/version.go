// Package version holds the collector's own version and the catalog-contract
// compatibility check. The collector refuses to run
// against a catalog whose contract version is outside its supported range.
package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	assets "thunderstorm/collector"
	"thunderstorm/collector/internal/model"
)

const (
	// CollectorVersion is the Thunderstorm collector's OWN version — independent of
	// the embedded RAGE snapshot (assets.RageVersion()), the catalog contract range,
	// the bundle schema, and the engine floor below. Bump freely for collector
	// changes without touching those compatibility contracts.
	CollectorVersion    = "0.2.0-dev"
	BundleSchemaVersion = "1.0.0"
	MinEngine           = "0.1.0"

	// SupportedCatalog is the semver range of catalog contract versions this
	// collector accepts. "Future collectors support existing catalogs" = keep
	// the lower bound, widen the upper. Form: ">=MAJOR.MINOR.PATCH <MAJOR.0.0".
	SupportedCatalogMinInclusive = "1.0.0"
	SupportedCatalogMaxExclusive = "2.0.0"
)

// SupportedRange renders the human-readable supported range.
func SupportedRange() string {
	return fmt.Sprintf(">=%s <%s", SupportedCatalogMinInclusive, SupportedCatalogMaxExclusive)
}

// compat is the subset of collectors/COMPATIBILITY.yaml we read.
type compat struct {
	CatalogContractVersion string `yaml:"catalog_contract_version"`
	CatalogHistory         []struct {
		Contract          string            `yaml:"contract"`
		ComponentVersions map[string]string `yaml:"component_versions"`
	} `yaml:"catalog_history"`
}

// LoadContract reads the catalog contract version + component versions from the
// repo's COMPATIBILITY.yaml (repoRoot/collectors/COMPATIBILITY.yaml) when running
// inside the repo, otherwise from the copy embedded in the binary.
func LoadContract(repoRoot string) (contractVersion string, components map[string]string, err error) {
	var b []byte
	if repoRoot != "" {
		if disk, e := os.ReadFile(filepath.Join(repoRoot, "collectors", "COMPATIBILITY.yaml")); e == nil {
			b = disk
		}
	}
	if b == nil {
		b, err = assets.FS.ReadFile("COMPATIBILITY.yaml")
		if err != nil {
			return "", nil, fmt.Errorf("reading embedded COMPATIBILITY.yaml: %w", err)
		}
	}
	var c compat
	if err := yaml.Unmarshal(b, &c); err != nil {
		return "", nil, fmt.Errorf("parsing COMPATIBILITY.yaml: %w", err)
	}
	if c.CatalogContractVersion == "" {
		return "", nil, fmt.Errorf("COMPATIBILITY.yaml: catalog_contract_version is empty")
	}
	// component versions from the history entry matching the current contract
	for _, h := range c.CatalogHistory {
		if h.Contract == c.CatalogContractVersion {
			components = h.ComponentVersions
		}
	}
	return c.CatalogContractVersion, components, nil
}

// CheckCompatible verifies the catalog contract version is within the supported
// range. Fails loud with an actionable message rather than guessing.
func CheckCompatible(contractVersion string) error {
	v, err := parseSemver(contractVersion)
	if err != nil {
		return fmt.Errorf("catalog contract version %q: %w", contractVersion, err)
	}
	lo, _ := parseSemver(SupportedCatalogMinInclusive)
	hi, _ := parseSemver(SupportedCatalogMaxExclusive)
	if cmp(v, lo) < 0 || cmp(v, hi) >= 0 {
		return fmt.Errorf(
			"collector %s supports catalog %s; found %s — upgrade the collector (or pin the catalog)",
			CollectorVersion, SupportedRange(), contractVersion)
	}
	return nil
}

// Block builds the VersionBlock for a bundle manifest.
func Block(contractVersion string, components map[string]string) model.VersionBlock {
	return model.VersionBlock{
		CollectorVersion:       CollectorVersion,
		CatalogContractVersion: contractVersion,
		ComponentVersions:      components,
		SupportedCatalog:       SupportedRange(),
		BundleSchemaVersion:    BundleSchemaVersion,
		MinEngine:              MinEngine,
	}
}

type semver struct{ major, minor, patch int }

func parseSemver(s string) (semver, error) {
	// tolerate a "-dev"/pre-release suffix on the patch
	s = strings.SplitN(s, "-", 2)[0]
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("not MAJOR.MINOR.PATCH")
	}
	var out semver
	var err error
	if out.major, err = strconv.Atoi(parts[0]); err != nil {
		return semver{}, err
	}
	if out.minor, err = strconv.Atoi(parts[1]); err != nil {
		return semver{}, err
	}
	if out.patch, err = strconv.Atoi(parts[2]); err != nil {
		return semver{}, err
	}
	return out, nil
}

func cmp(a, b semver) int {
	switch {
	case a.major != b.major:
		return a.major - b.major
	case a.minor != b.minor:
		return a.minor - b.minor
	default:
		return a.patch - b.patch
	}
}
