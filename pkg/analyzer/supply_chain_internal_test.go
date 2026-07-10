package analyzer

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestExtractDependencies_RejectsTopLevelNull(t *testing.T) {
	t.Parallel()

	_, err := extractDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": nil,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supply_chain: dependencies metadata must be an array")
}

func TestCollectDependencies_SkipsNullMetadataEntries(t *testing.T) {
	t.Parallel()

	deps, err := collectDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": []any{
			nil,
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
		},
	}))
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "axios", deps[0].Name)
	assert.Equal(t, "1.14.1", deps[0].Version)
	assert.Equal(t, "npm", deps[0].Ecosystem)
	assert.Equal(t, "metadata", deps[0].Source)
}

func TestCollectDependencies_SkipsEntriesMissingRequiredFields(t *testing.T) {
	t.Parallel()

	deps, err := collectDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": []any{
			map[string]any{"name": "", "version": "1.14.1", "ecosystem": "npm"},
			map[string]any{"name": "axios", "version": "", "ecosystem": "npm"},
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": ""},
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
		},
	}))
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "axios", deps[0].Name)
	assert.Equal(t, "1.14.1", deps[0].Version)
	assert.Equal(t, "npm", deps[0].Ecosystem)
	assert.Equal(t, "metadata", deps[0].Source)
}

func TestCollectDependencies_WhitespaceSourceFallsBackToMetadata(t *testing.T) {
	t.Parallel()

	deps, err := collectDependencies(toolWithMetadataForTest(map[string]any{
		"dependencies": []any{
			map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm", "source": "   "},
		},
	}))
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "metadata", deps[0].Source)
}

func TestCollectDependencies_IgnoresWhitespaceRepoURL(t *testing.T) {
	var called bool
	prev := lockfileDepsFetcher
	lockfileDepsFetcher = func(string) []Dependency {
		called = true
		return []Dependency{{Name: "axios", Version: "1.14.1", Ecosystem: "npm"}}
	}
	t.Cleanup(func() {
		lockfileDepsFetcher = prev
	})

	deps, err := collectDependencies(toolWithMetadataForTest(map[string]any{
		"repo_url": "   ",
	}))
	require.NoError(t, err)
	assert.False(t, called)
	assert.Empty(t, deps)
}

func TestRawGitHubURL_RejectsLookalikeHost(t *testing.T) {
	t.Parallel()

	rawURL, ok := rawGitHubURL("https://notgithub.com/example/repo", "main", "go.sum")

	assert.False(t, ok)
	assert.Empty(t, rawURL)
}

func TestRawGitHubURL_NormalizesCloneURL(t *testing.T) {
	t.Parallel()

	rawURL, ok := rawGitHubURL("git+https://github.com/example/repo.git/", "main", "go.sum")

	require.True(t, ok)
	assert.Equal(t, "https://raw.githubusercontent.com/example/repo/main/go.sum", rawURL)
}

func TestFetchLockfileDeps_RejectsOversizedRequirementsFile(t *testing.T) {
	filler := strings.Repeat("# padding\n", lockfileFetchLimit/len("# padding\n")+1)
	body := "visible==1.0.0\n" + filler + "hidden==2.0.0\n"
	require.Greater(t, len(body), lockfileFetchLimit)

	previousTransport := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		status := http.StatusNotFound
		responseBody := ""
		if strings.HasSuffix(req.URL.Path, "/requirements.txt") {
			status = http.StatusOK
			responseBody = body
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	t.Cleanup(func() {
		http.DefaultTransport = previousTransport
	})

	deps := fetchLockfileDeps("https://github.com/example/repo")

	assert.Empty(t, deps)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func toolWithMetadataForTest(meta map[string]any) model.UnifiedTool {
	return model.UnifiedTool{
		Name:     "test-tool",
		Metadata: meta,
	}
}
