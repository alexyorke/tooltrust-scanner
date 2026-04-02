package analyzer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestSummarizeToolContext_UsesNetworkAndDynamicURLInput(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "fetch_remote",
		Description: "Fetch a remote resource over HTTPS.",
		Permissions: []model.Permission{model.PermissionNetwork},
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"url": {Type: "string", Description: "Remote URL to fetch"},
			},
		},
	}

	behavior, destinations := SummarizeToolContext(tool)

	assert.Equal(t, []string{"uses_network"}, behavior)
	assert.Equal(t, []string{"dynamic URL input (url)"}, destinations)
}

func TestSummarizeToolContext_ReadsEnvAndFindsHardcodedDomain(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"baseURL": "https://api.postmarkapp.com/email",
		},
	})

	tool := model.UnifiedTool{
		Name:        "send_email",
		Description: "Reads process.env.POSTMARK_TOKEN and sends mail via api.postmarkapp.com",
		Permissions: []model.Permission{model.PermissionNetwork, model.PermissionEnv},
		RawSource:   raw,
	}

	behavior, destinations := SummarizeToolContext(tool)

	assert.Equal(t, []string{"reads_env", "uses_network"}, behavior)
	assert.Contains(t, destinations, "hardcoded domain: api.postmarkapp.com")
}

func TestSummarizeToolContext_ReadsAndWritesFiles(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "write_file",
		Description: "Write updated contents to a file path.",
		Permissions: []model.Permission{model.PermissionFS},
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"path":    {Type: "string"},
				"content": {Type: "string"},
			},
		},
	}

	behavior, destinations := SummarizeToolContext(tool)

	assert.Equal(t, []string{"writes_files"}, behavior)
	assert.Empty(t, destinations)
}

func TestSummarizeToolContext_DetectsDynamicEmailRecipient(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "send_email",
		Description: "Send an email message.",
		Permissions: []model.Permission{model.PermissionNetwork},
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"bcc": {Type: "string", Description: "Blind copy recipient"},
			},
		},
	}

	_, destinations := SummarizeToolContext(tool)

	assert.Equal(t, []string{"dynamic email recipient (bcc)"}, destinations)
}
