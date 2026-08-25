package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPOSVClient_Query_RejectsTopLevelNullResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("null"))
	}))
	defer srv.Close()

	client := &httpOSVClient{
		http:    srv.Client(),
		baseURL: srv.URL,
	}

	_, err := client.Query(context.Background(), Dependency{
		Name:      "lodash",
		Version:   "4.17.15",
		Ecosystem: "npm",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "osv: top-level JSON value must be an object")
}

func TestHTTPOSVClient_Query_RejectsTopLevelArrayResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	client := &httpOSVClient{
		http:    srv.Client(),
		baseURL: srv.URL,
	}

	_, err := client.Query(context.Background(), Dependency{
		Name:      "lodash",
		Version:   "4.17.15",
		Ecosystem: "npm",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "osv: top-level JSON value must be an object")
}
