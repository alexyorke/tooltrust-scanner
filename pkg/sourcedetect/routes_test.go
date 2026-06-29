package sourcedetect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractRouteRegistrations_RawStringPath(t *testing.T) {
	text := "func Register(api Router, mcpHandler Handler) {\n" +
		"\tapi.Any(`/mcp_message`, func(c *Context) {\n" +
		"\t\tmcpHandler.ServeHTTP(c)\n" +
		"\t})\n" +
		"}\n"

	routes := extractRouteRegistrations("router.go", text)

	require.Len(t, routes, 1)
	assert.Equal(t, "/mcp_message", routes[0].Path)
	assert.Equal(t, "mcpHandler.ServeHTTP", routes[0].Handler)
}

func TestExtractRouteRegistrations_UsesMCPPathFromChainedGroup(t *testing.T) {
	text := `func Register(api Router, mcpHandler Handler) {
	api.Group("/api").Any("/mcp_message", func(c *Context) {
		mcpHandler.ServeHTTP(c)
	})
}
`

	routes := extractRouteRegistrations("router.go", text)

	require.Len(t, routes, 1)
	assert.Equal(t, "/mcp_message", routes[0].Path)
	assert.Equal(t, "mcpHandler.ServeHTTP", routes[0].Handler)
}

func TestExtractRouteRegistrations_DirectHandlerArgument(t *testing.T) {
	text := `func Register(api Router, mcpHandler Handler) {
	api.Any("/mcp_message", mcpHandler)
}
`

	routes := extractRouteRegistrations("router.go", text)

	require.Len(t, routes, 1)
	assert.Equal(t, "/mcp_message", routes[0].Path)
	assert.Equal(t, "mcpHandler", routes[0].Handler)
}

func TestExtractRouteRegistrations_HandleFunc(t *testing.T) {
	text := `func Register(mux Router, mcpHandler Handler) {
	mux.HandleFunc("/mcp_message", mcpHandler)
}
`

	routes := extractRouteRegistrations("router.go", text)

	require.Len(t, routes, 1)
	assert.Equal(t, "/mcp_message", routes[0].Path)
	assert.Equal(t, "mcpHandler", routes[0].Handler)
}
