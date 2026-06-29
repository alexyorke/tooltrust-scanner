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

func TestExtractRouteRegistrations_MiddlewareWrappedDirectHandler(t *testing.T) {
	text := `func Register(api Router, mcpHandler Handler, allowed []string) {
	api.Any("/mcp", AuthRequired(mcpHandler))
	api.Any("/mcp_message", IPWhitelist(allowed, mcpHandler))
}
`

	routes := extractRouteRegistrations("router.go", text)

	require.Len(t, routes, 2)
	assert.Equal(t, "/mcp", routes[0].Path)
	assert.Equal(t, "mcpHandler", routes[0].Handler)
	assert.True(t, routes[0].HasAuth)
	assert.False(t, routes[0].HasIPFilter)
	assert.Equal(t, "/mcp_message", routes[1].Path)
	assert.Equal(t, "mcpHandler", routes[1].Handler)
	assert.False(t, routes[1].HasAuth)
	assert.True(t, routes[1].HasIPFilter)
}

func TestExtractRouteRegistrations_MiddlewareArgumentBeforeDirectHandler(t *testing.T) {
	text := `func Register(api Router, mcpHandler Handler) {
	api.Any("/mcp", AuthRequired(), mcpHandler)
	api.Any("/mcp_message", mcpHandler)
}
`

	routes := extractRouteRegistrations("router.go", text)

	require.Len(t, routes, 2)
	assert.Equal(t, "/mcp", routes[0].Path)
	assert.Equal(t, "mcpHandler", routes[0].Handler)
	assert.True(t, routes[0].HasAuth)
	assert.Equal(t, "/mcp_message", routes[1].Path)
	assert.Equal(t, "mcpHandler", routes[1].Handler)
	assert.False(t, routes[1].HasAuth)
}
