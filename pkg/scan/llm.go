package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LLMConfig configures an OpenAI-compatible chat-completions endpoint.
type LLMConfig struct {
	Provider string // preset name or "custom"
	BaseURL  string // e.g. https://api.openai.com/v1
	APIKey   string
	Model    string
	// Timeout bounds a single HTTP request.
	Timeout time.Duration
}

// Message is one chat message; ToolCalls is set on assistant messages.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall is a model-requested tool invocation.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ToolDefinition describes a callable tool to the model.
type ToolDefinition struct {
	Type     string             `json:"type"`
	Function FunctionDefinition `json:"function"`
}

// FunctionDefinition is the JSON-schema description of one tool.
type FunctionDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type chatRequest struct {
	Model       string           `json:"model"`
	Messages    []Message        `json:"messages"`
	Tools       []ToolDefinition `json:"tools,omitempty"`
	Temperature float64          `json:"temperature"`
	MaxTokens   int              `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// LLM is a minimal OpenAI-compatible client.
type LLM struct {
	cfg  LLMConfig
	http *http.Client
}

func NewLLM(cfg LLMConfig) *LLM {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	return &LLM{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}
}

// Chat performs one non-streaming chat completion.
func (l *LLM) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (Message, error) {
	body, err := json.Marshal(chatRequest{
		Model:    l.cfg.Model,
		Messages: messages,
		Tools:    tools,
		// Low temperature: this is an audit, not a creative task.
		Temperature: 0,
		MaxTokens:   4096,
	})
	if err != nil {
		return Message{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+l.cfg.APIKey)
	}
	resp, err := l.http.Do(req)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return Message{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Message{}, fmt.Errorf("LLM endpoint returned %s: %s", resp.Status, truncate(string(payload), 400))
	}
	var parsed chatResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return Message{}, fmt.Errorf("cannot decode LLM response: %w", err)
	}
	if parsed.Error != nil {
		return Message{}, errors.New(parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return Message{}, errors.New("LLM returned no choices")
	}
	return parsed.Choices[0].Message, nil
}
