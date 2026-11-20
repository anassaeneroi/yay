package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Provider is a named OpenAI-compatible endpoint preset. Anthropic, Gemini,
// OpenRouter, Groq and the local runtimes all speak the same
// chat-completions protocol, so one client covers every provider.
type Provider struct {
	Name         string
	BaseURL      string
	KeyEnv       []string // tried in order; empty means no key required
	DefaultModel string   // empty means discover from the endpoint's /models
	Local        bool     // local runtime: no key, model discovery allowed
}

// Providers maps YAY_SCAN_PROVIDER values to endpoint presets.
var Providers = map[string]Provider{
	"openai":     {Name: "openai", BaseURL: "https://api.openai.com/v1", KeyEnv: []string{"OPENAI_API_KEY"}, DefaultModel: "gpt-4o-mini"},
	"anthropic":  {Name: "anthropic", BaseURL: "https://api.anthropic.com/v1", KeyEnv: []string{"ANTHROPIC_API_KEY"}, DefaultModel: "claude-haiku-4-5"},
	"gemini":     {Name: "gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", KeyEnv: []string{"GEMINI_API_KEY", "GOOGLE_API_KEY"}, DefaultModel: "gemini-2.5-flash"},
	"openrouter": {Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", KeyEnv: []string{"OPENROUTER_API_KEY"}, DefaultModel: "openai/gpt-4o-mini"},
	"groq":       {Name: "groq", BaseURL: "https://api.groq.com/openai/v1", KeyEnv: []string{"GROQ_API_KEY"}, DefaultModel: "llama-3.3-70b-versatile"},
	"deepseek":   {Name: "deepseek", BaseURL: "https://api.deepseek.com/v1", KeyEnv: []string{"DEEPSEEK_API_KEY"}, DefaultModel: "deepseek-chat"},
	"mistral":    {Name: "mistral", BaseURL: "https://api.mistral.ai/v1", KeyEnv: []string{"MISTRAL_API_KEY"}, DefaultModel: "mistral-small-latest"},
	"xai":        {Name: "xai", BaseURL: "https://api.x.ai/v1", KeyEnv: []string{"XAI_API_KEY"}, DefaultModel: "grok-3-mini"},
	"ollama":     {Name: "ollama", BaseURL: "http://localhost:11434/v1", Local: true},
	"lmstudio":   {Name: "lmstudio", BaseURL: "http://localhost:1234/v1", Local: true},
	"vllm":       {Name: "vllm", BaseURL: "http://localhost:8000/v1", Local: true},
}

// ProviderNames lists preset names for docs and error messages.
func ProviderNames() []string {
	names := make([]string, 0, len(Providers))
	for name := range Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResolveLLMConfig builds the endpoint configuration from the environment.
//
// Precedence:
//  1. YAY_SCAN_PROVIDER preset (YAY_SCAN_BASE_URL / YAY_SCAN_API_KEY /
//     YAY_SCAN_MODEL override individual preset fields);
//  2. YAY_SCAN_BASE_URL alone: custom OpenAI-compatible endpoint;
//  3. legacy OPENAI_BASE_URL / OPENAI_API_KEY / OPENAI_MODEL;
//  4. otherwise scanning runs static-only and the error says why.
//
// Local providers without an explicit model discover one from the runtime's
// /models listing, so `YAY_SCAN_PROVIDER=ollama` works with no other setup.
func ResolveLLMConfig() (LLMConfig, error) {
	get := func(keys ...string) string {
		for _, key := range keys {
			if key != "" {
				if v := os.Getenv(key); v != "" {
					return v
				}
			}
		}
		return ""
	}

	cfg := LLMConfig{
		BaseURL: get("YAY_SCAN_BASE_URL"),
		APIKey:  get("YAY_SCAN_API_KEY"),
		Model:   get("YAY_SCAN_MODEL"),
		Timeout: 90 * time.Second,
	}

	if name := get("YAY_SCAN_PROVIDER"); name != "" {
		preset, ok := Providers[strings.ToLower(name)]
		if !ok {
			return cfg, fmt.Errorf("unknown YAY_SCAN_PROVIDER %q (valid: %s, or set YAY_SCAN_BASE_URL for a custom endpoint)",
				name, strings.Join(ProviderNames(), ", "))
		}
		cfg.Provider = preset.Name
		if cfg.BaseURL == "" {
			// YAY_SCAN_BASE_URL also overrides a preset, e.g. Ollama on a LAN host.
			cfg.BaseURL = preset.BaseURL
		}
		if cfg.APIKey == "" {
			cfg.APIKey = get(preset.KeyEnv...)
		}
		if cfg.Model == "" {
			cfg.Model = preset.DefaultModel
		}
		if !preset.Local && cfg.APIKey == "" {
			return cfg, fmt.Errorf("provider %s needs an API key: set %s or YAY_SCAN_API_KEY",
				preset.Name, strings.Join(preset.KeyEnv, " or "))
		}
	} else if cfg.BaseURL != "" {
		// Explicit custom endpoint; nothing else required.
		cfg.Provider = "custom"
		if cfg.Model == "" {
			cfg.Model = get("OPENAI_MODEL")
		}
		if cfg.APIKey == "" {
			cfg.APIKey = get("OPENAI_API_KEY")
		}
	} else {
		// Legacy fallback: an already-configured OpenAI-compatible environment.
		cfg.BaseURL = get("OPENAI_BASE_URL")
		cfg.APIKey = get("OPENAI_API_KEY")
		cfg.Model = get("OPENAI_MODEL")
		cfg.Provider = "custom"
		if cfg.BaseURL == "" {
			return cfg, errors.New("no LLM endpoint configured: set YAY_SCAN_PROVIDER (" +
				strings.Join(ProviderNames(), ", ") + ") or YAY_SCAN_BASE_URL; running static checks only")
		}
	}

	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if cfg.Model == "" {
		model, err := discoverModel(cfg)
		if err != nil {
			return cfg, fmt.Errorf("no model configured and discovery failed: %w (set YAY_SCAN_MODEL)", err)
		}
		cfg.Model = model
	}
	return cfg, nil
}

// discoverModel asks an OpenAI-compatible endpoint which models it serves and
// returns the first one. Used for local runtimes (Ollama, LM Studio, vLLM).
func discoverModel(cfg LLMConfig) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, cfg.BaseURL+"/models", nil)
	if err != nil {
		return "", err
	}
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("endpoint returned %s", resp.Status)
	}
	var listing struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&listing); err != nil {
		return "", err
	}
	if len(listing.Data) == 0 || listing.Data[0].ID == "" {
		return "", errors.New("endpoint serves no models (e.g. run `ollama pull qwen2.5:7b` first)")
	}
	return listing.Data[0].ID, nil
}
