package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// TestDetectLocalProjectRoot_PublishedPackage verifies that a bare published-package
// launch command (npx -y <pkg>) does NOT pick up the CWD as the local project root,
// even if the CWD contains a go.mod / go.sum. This is the core fix for AS-004 FP.
func TestDetectLocalProjectRoot_PublishedPackage(t *testing.T) {
	tmp := t.TempDir()
	// Plant a go.mod so the old CWD-based heuristic would have found this dir.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(`module example.com/host

go 1.21
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.sum"), []byte(""), 0o644))

	t.Chdir(tmp)

	// "npx -y lichess-mcp" names a published package — no local path in args.
	got := detectLocalProjectRoot([]string{"npx", "-y", "lichess-mcp"})
	assert.Equal(t, "", got,
		"published-package launch must not infer a local project root from the CWD")
}

// TestDetectLocalProjectRoot_LocalScript verifies that arg-based detection still works:
// "node ./server.js" references a local path, so the project root containing
// package.json in the CWD should be returned.
func TestDetectLocalProjectRoot_LocalScript(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"demo"}`), 0o644))
	// Create the script file so os.Stat succeeds on the resolved path.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "server.js"), []byte("// stub"), 0o644))

	t.Chdir(tmp)

	got := detectLocalProjectRoot([]string{"node", "./server.js"})
	assert.Equal(t, tmp, got,
		"local-script launch must return the project root via arg-based detection")
}

func TestDetectLocalProjectRoot_LocalPythonScriptBareFilename(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "server.py"), []byte("# stub\n"), 0o644))

	t.Chdir(tmp)

	got := detectLocalProjectRoot([]string{"python", "server.py"})
	assert.Equal(t, tmp, got,
		"bare local Python script launches must return the project root")
}

func TestDetectLocalProjectRoot_LocalGoFileBareFilename(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/demo\n\ngo 1.21\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644))

	t.Chdir(tmp)

	got := detectLocalProjectRoot([]string{"go", "run", "main.go"})
	assert.Equal(t, tmp, got,
		"bare local Go file launches must return the project root")
}

func TestSplitServerCommand_PreservesLeadingEnvAssignments(t *testing.T) {
	command, env, args, err := splitServerCommand(`API_KEY=secret OTHER=value node ./server.js --flag`)
	require.NoError(t, err)

	assert.Equal(t, "node", command)
	assert.Equal(t, []string{"API_KEY=secret", "OTHER=value"}, env)
	assert.Equal(t, []string{"./server.js", "--flag"}, args)
}

func TestSplitServerCommand_RejectsOnlyEnvAssignments(t *testing.T) {
	_, _, _, err := splitServerCommand(`API_KEY=secret`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty server command")
}

func TestMergeDependencies_PrefersStrongerSourceForDuplicateDependency(t *testing.T) {
	tool := &model.UnifiedTool{
		Metadata: map[string]any{
			"dependencies": []map[string]any{
				{"name": "axios", "version": "1.14.1", "ecosystem": "npm", "source": "metadata"},
			},
		},
	}

	mergeDependencies(tool, []nodeDependency{
		{Name: "axios", Version: "1.14.1", Ecosystem: "npm", Source: "local_lockfile"},
	})

	rawDeps, ok := tool.Metadata["dependencies"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, rawDeps, 1)
	assert.Equal(t, "local_lockfile", rawDeps[0]["source"])
}

func TestMergeDependencies_NormalizesCaseAndVersionBeforeDeduping(t *testing.T) {
	tool := &model.UnifiedTool{
		Metadata: map[string]any{
			"dependencies": []map[string]any{
				{"name": "litellm", "version": "v1.82.8", "ecosystem": "pypi", "source": "metadata"},
			},
		},
	}

	mergeDependencies(tool, []nodeDependency{
		{Name: "litellm", Version: "1.82.8", Ecosystem: "PyPI", Source: "local_lockfile"},
	})

	rawDeps, ok := tool.Metadata["dependencies"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, rawDeps, 1)
	assert.Equal(t, "local_lockfile", rawDeps[0]["source"])
}

func TestParseYarnLockfile_NPMAliasUsesRealPackageName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yarn.lock")
	require.NoError(t, os.WriteFile(path, []byte(`
"string-width-cjs@npm:string-width@^4.2.0":
  version "4.2.3"
`), 0o644))

	deps, err := parseYarnLockfile(path)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "string-width", deps[0].Name)
	assert.Equal(t, "4.2.3", deps[0].Version)
	assert.Equal(t, "npm", deps[0].Ecosystem)
	assert.Equal(t, "local_lockfile", deps[0].Source)
}

func TestParseNodeLockfile_NPMAliasUsesRealPackageName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package-lock.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "packages": {
    "": {
      "version": "1.0.0",
      "dependencies": {
        "string-width-cjs": "npm:string-width@^4.2.3"
      }
    },
    "node_modules/string-width-cjs": {
      "name": "string-width",
      "version": "4.2.3"
    }
  }
}`), 0o644))

	deps, err := parseNodeLockfile(path)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "string-width", deps[0].Name)
	assert.Equal(t, "4.2.3", deps[0].Version)
	assert.Equal(t, "npm", deps[0].Ecosystem)
	assert.Equal(t, "local_lockfile", deps[0].Source)
}
