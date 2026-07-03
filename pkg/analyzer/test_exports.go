package analyzer

import (
	"context"
	"fmt"
	"time"
)

// SetLockfileDepsFetcherForTest overrides the lockfile dependency fetcher.
// Intended for tests only.
func SetLockfileDepsFetcherForTest(fn func(string) []Dependency) {
	lockfileDepsFetcher = fn
}

// LockfileDepsFetcherForTest returns the current lockfile fetcher.
// Intended for tests only.
func LockfileDepsFetcherForTest() func(string) []Dependency {
	return lockfileDepsFetcher
}

// NPMVersionResponseForTest exposes npmVersionResponse for analyzer_test.
type NPMVersionResponseForTest = npmVersionResponse

// ParsePNPMLockYAMLForTest exposes parsePNPMLockYAML for analyzer_test.
func ParsePNPMLockYAMLForTest(data []byte) ([]Dependency, error) {
	return parsePNPMLockYAML(data)
}

// ParseYarnLockForTest exposes parseYarnLock for analyzer_test.
func ParseYarnLockForTest(data []byte) ([]Dependency, error) {
	return parseYarnLock(data)
}

// NPMIOCEntryForTest exposes npmIOCEntry for analyzer_test.
type NPMIOCEntryForTest = npmIOCEntry

// BuildNPMIOCIndexForTest exposes buildNPMIOCIndex for analyzer_test.
func BuildNPMIOCIndexForTest(data []byte) (map[string]npmIOCEntry, error) {
	idx, err := buildNPMIOCIndex(data)
	if err != nil {
		return nil, err
	}
	return idx.packageNames, nil
}

// BuildNPMIOCIndexForRuntimeTest exposes the full runtime IOC index for analyzer_test.
func BuildNPMIOCIndexForRuntimeTest(data []byte) (npmIOCIndex, error) {
	return buildNPMIOCIndex(data)
}

// NewNPMIOCCheckerWithIndexForTest overrides the IOC index for analyzer_test.
func NewNPMIOCCheckerWithIndexForTest(checker *NPMIOCChecker, index npmIOCIndex) *NPMIOCChecker {
	checker.index = index
	return checker
}

// NPMRegistryClientForTest exposes the npm registry client contract to tests.
type NPMRegistryClientForTest interface {
	FetchVersion(context.Context, string, string) (NPMVersionResponseForTest, error)
}

type npmRegistryClientTestAdapter struct {
	client NPMRegistryClientForTest
}

func (a npmRegistryClientTestAdapter) FetchVersion(ctx context.Context, pkg, version string) (npmVersionResponse, error) {
	resp, err := a.client.FetchVersion(ctx, pkg, version)
	if err != nil {
		return npmVersionResponse{}, fmt.Errorf("npm test client fetch: %w", err)
	}
	return resp, nil
}

// NewNPMLifecycleScriptCheckerWithClientForTest overrides the registry client for tests.
func NewNPMLifecycleScriptCheckerWithClientForTest(client NPMRegistryClientForTest) *NPMLifecycleScriptChecker {
	return &NPMLifecycleScriptChecker{client: npmRegistryClientTestAdapter{client: client}}
}

// NewNPMIOCCheckerWithClientForTest overrides the registry client for tests.
func NewNPMIOCCheckerWithClientForTest(client NPMRegistryClientForTest) *NPMIOCChecker {
	return &NPMIOCChecker{client: npmRegistryClientTestAdapter{client: client}, index: loadEmbeddedNPMIOCIndex()}
}

// SetNPMQueryTimeoutForTest overrides the shared NPM registry timeout.
func SetNPMQueryTimeoutForTest(d time.Duration) {
	npmQueryTimeout = d
}

// NPMQueryTimeoutForTest returns the current NPM registry timeout.
func NPMQueryTimeoutForTest() time.Duration {
	return npmQueryTimeout
}
