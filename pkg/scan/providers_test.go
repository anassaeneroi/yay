package scan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearScanEnv blanks every variable that can influence ResolveLLMConfig.
func clearScanEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"YAY_SCAN_BASE_URL", "YAY_SCAN_API_KEY", "YAY_SCAN_MODEL", "YAY_SCAN_PROVIDER",
		"OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL",
		"ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY",
		"GROQ_API_KEY", "DEEPSEEK_API_KEY", "MISTRAL_API_KEY", "XAI_API_KEY",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func TestResolveUnconfigured(t *testing.T) {
	clearScanEnv(t)
	_, err := ResolveLLMConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YAY_SCAN_PROVIDER")
	assert.Contains(t, err.Error(), "static checks only")
}

func TestResolveLegacyOpenAIEnv(t *testing.T) {
	clearScanEnv(t)
	t.Setenv("OPENAI_BASE_URL", "https://gateway.example/v1/")
	t.Setenv("OPENAI_API_KEY", "k")
	t.Setenv("OPENAI_MODEL", "some-model")
	cfg, err := ResolveLLMConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://gateway.example/v1", cfg.BaseURL)
	assert.Equal(t, "some-model", cfg.Model)
	assert.Equal(t, "k", cfg.APIKey)
}

func TestResolveProviderPresets(t *testing.T) {
	for name, preset := range Providers {
		t.Run(name, func(t *testing.T) {
			clearScanEnv(t)
			t.Setenv("YAY_SCAN_PROVIDER", name)
			t.Setenv("YAY_SCAN_MODEL", "explicit-model") // skip local discovery
			if !preset.Local {
				t.Setenv(preset.KeyEnv[0], "secret")
			}
			cfg, err := ResolveLLMConfig()
			require.NoError(t, err)
			assert.Equal(t, name, cfg.Provider)
			assert.Equal(t, preset.BaseURL, cfg.BaseURL)
			assert.Equal(t, "explicit-model", cfg.Model)
			if !preset.Local {
				assert.Equal(t, "secret", cfg.APIKey)
			}
		})
	}
}

func TestResolveProviderDefaultModel(t *testing.T) {
	clearScanEnv(t)
	t.Setenv("YAY_SCAN_PROVIDER", "anthropic")
	t.Setenv("ANTHROPIC_API_KEY", "secret")
	cfg, err := ResolveLLMConfig()
	require.NoError(t, err)
	assert.Equal(t, Providers["anthropic"].DefaultModel, cfg.Model)
}

func TestResolveProviderMissingKey(t *testing.T) {
	clearScanEnv(t)
	t.Setenv("YAY_SCAN_PROVIDER", "groq")
	_, err := ResolveLLMConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GROQ_API_KEY")
}

func TestResolveUnknownProvider(t *testing.T) {
	clearScanEnv(t)
	t.Setenv("YAY_SCAN_PROVIDER", "hal-9000")
	_, err := ResolveLLMConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown YAY_SCAN_PROVIDER")
}

func TestResolveLocalModelDiscovery(t *testing.T) {
	clearScanEnv(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, "/models", r.URL.Path)
		fmt.Fprint(w, `{"data":[{"id":"qwen2.5:7b"}]}`)
	}))
	defer server.Close()

	t.Setenv("YAY_SCAN_PROVIDER", "ollama")
	t.Setenv("YAY_SCAN_BASE_URL", server.URL) // e.g. Ollama on another host
	cfg, err := ResolveLLMConfig()
	require.NoError(t, err)
	assert.Equal(t, "qwen2.5:7b", cfg.Model)
	assert.Equal(t, "ollama", cfg.Provider)
	assert.Empty(t, cfg.APIKey, "local runtimes must not require an API key")
	assert.Equal(t, 1, requests)
}

func TestResolveLocalDiscoveryEmpty(t *testing.T) {
	clearScanEnv(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer server.Close()
	t.Setenv("YAY_SCAN_PROVIDER", "lmstudio")
	t.Setenv("YAY_SCAN_BASE_URL", server.URL)
	_, err := ResolveLLMConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no models")
}

func TestResolveLocalUnreachable(t *testing.T) {
	clearScanEnv(t)
	t.Setenv("YAY_SCAN_PROVIDER", "ollama")
	t.Setenv("YAY_SCAN_BASE_URL", "http://127.0.0.1:1")
	_, err := ResolveLLMConfig()
	require.Error(t, err, "an unreachable local runtime must not silently pass as configured")
	assert.Contains(t, err.Error(), "YAY_SCAN_MODEL")
}
