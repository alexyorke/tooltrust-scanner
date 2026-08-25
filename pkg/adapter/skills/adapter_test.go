package skills_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/skills"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestAdapter_Protocol(t *testing.T) {
	a := skills.NewAdapter()
	assert.Equal(t, model.ProtocolSkills, a.Protocol())
}

func TestAdapter_Parse_ReturnsNotImplemented(t *testing.T) {
	_, err := skills.NewAdapter().Parse(context.Background(), []byte(""))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}
