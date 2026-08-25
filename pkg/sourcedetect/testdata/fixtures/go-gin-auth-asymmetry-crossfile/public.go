package router

import "github.com/mark3labs/mcp-go/server"

func RegisterPublic(api Router, mcpHandler *server.StreamableHTTPServer) {
	api.Any("/mcp_message", IPWhiteList(), func(c *Context) {
		mcpHandler.ServeHTTP(c)
	})
}
