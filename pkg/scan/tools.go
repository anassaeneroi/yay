package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Tool output limits keep observations bounded in the model context.
const (
	toolMaxReadLines   = 400
	toolMaxLineLength  = 400
	toolMaxListEntries = 500
	toolMaxSearchHits  = 50
	toolMaxOutputBytes = 32 << 10
)

// Tools is the fixed, read-only tool layer exposed to the agent.
// There is deliberately no shell/exec tool. Every path is confined to root,
// including after symlink resolution.
type Tools struct {
	root string
}

func NewTools(root string) *Tools { return &Tools{root: root} }

// Definitions returns the OpenAI-compatible tool schemas.
func (t *Tools) Definitions() []ToolDefinition {
	return []ToolDefinition{
		{
			Type: "function",
			Function: FunctionDefinition{
				Name:        "list_files",
				Description: "List files in the package build directory (relative paths and sizes). Use to discover PKGBUILD, .install scripts and downloaded sources.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{"type": "string", "description": "Subdirectory relative to the build root; empty for the root."},
					},
				},
			},
		},
		{
			Type: "function",
			Function: FunctionDefinition{
				Name:        "read_file",
				Description: "Read a text file with line numbers. Large files must be paged with offset/limit.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path":   map[string]any{"type": "string"},
						"offset": map[string]any{"type": "integer", "description": "1-based first line, default 1."},
						"limit":  map[string]any{"type": "integer", "description": "Max lines, default 200, max 400."},
					},
					"required": []string{"path"},
				},
			},
		},
		{
			Type: "function",
			Function: FunctionDefinition{
				Name:        "search",
				Description: "Search all text files with a regular expression; returns file:line: text matches.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"pattern": map[string]any{"type": "string"},
					},
					"required": []string{"pattern"},
				},
			},
		},
	}
}

// Call executes one tool and returns its textual observation. Errors are
// returned as observations too, so the model can correct its own arguments.
func (t *Tools) Call(name, argsJSON string) string {
	var out string
	var err error
	switch name {
	case "list_files":
		var args struct {
			Path string `json:"path"`
		}
		if err = json.Unmarshal([]byte(argsJSON), &args); err == nil {
			out, err = t.listFiles(args.Path)
		}
	case "read_file":
		var args struct {
			Path   string `json:"path"`
			Offset int    `json:"offset"`
			Limit  int    `json:"limit"`
		}
		if err = json.Unmarshal([]byte(argsJSON), &args); err == nil {
			out, err = t.readFile(args.Path, args.Offset, args.Limit)
		}
	case "search":
		var args struct {
			Pattern string `json:"pattern"`
		}
		if err = json.Unmarshal([]byte(argsJSON), &args); err == nil {
			out, err = t.search(args.Pattern)
		}
	default:
		err = fmt.Errorf("unknown tool %q; only list_files, read_file and search are available", name)
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return truncate(out, toolMaxOutputBytes)
}

// resolve confines a user-supplied relative path to the scan root.
func (t *Tools) resolve(p string) (string, error) {
	if p == "" {
		p = "."
	}
	if filepath.IsAbs(p) {
		return "", errors.New("absolute paths are not allowed; use paths relative to the build root")
	}
	joined := filepath.Join(t.root, filepath.Clean(p))
	rootEval, err := filepath.EvalSymlinks(t.root)
	if err != nil {
		return "", err
	}
	eval, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", p, err)
	}
	if eval != rootEval && !strings.HasPrefix(eval, rootEval+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the package build directory", p)
	}
	return joined, nil
}

func (t *Tools) listFiles(sub string) (string, error) {
	dir, err := t.resolve(sub)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	entries := 0
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if d.Name() == ".git" && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if entries >= toolMaxListEntries {
			return fs.SkipAll
		}
		entries++
		size := int64(0)
		if info, infoErr := d.Info(); infoErr == nil {
			size = info.Size()
		}
		fmt.Fprintf(&b, "%s\t%d\n", relativePath(t.root, path), size)
		return nil
	})
	if walkErr != nil {
		return "", walkErr
	}
	if entries == 0 {
		return "(no files)", nil
	}
	return b.String(), nil
}

func (t *Tools) readFile(p string, offset, limit int) (string, error) {
	path, err := t.resolve(p)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if isBinary(data) {
		return "", fmt.Errorf("%q is binary; use search or inspect its references instead", p)
	}
	if offset < 1 {
		offset = 1
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > toolMaxReadLines {
		limit = toolMaxReadLines
	}
	lines := strings.Split(string(data), "\n")
	if offset > len(lines) {
		return fmt.Sprintf("(file has %d lines; offset %d is past the end)", len(lines), offset), nil
	}
	end := offset + limit - 1
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: lines %d-%d of %d\n", p, offset, end, len(lines))
	for i := offset; i <= end; i++ {
		fmt.Fprintf(&b, "%5d\t%s\n", i, truncate(lines[i-1], toolMaxLineLength))
	}
	return b.String(), nil
}

func (t *Tools) search(pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regular expression: %w", err)
	}
	hits := []string{}
	walkErr := filepath.WalkDir(t.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || len(hits) >= toolMaxSearchHits {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if d.Name() == ".git" && path != t.root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, statErr := d.Info(); statErr != nil || info.Size() > staticMaxFileSize {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil || isBinary(data) {
			return nil
		}
		rel := relativePath(t.root, path)
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				hits = append(hits, fmt.Sprintf("%s:%d: %s", rel, i+1, truncate(strings.TrimSpace(line), toolMaxLineLength)))
				if len(hits) >= toolMaxSearchHits {
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		return "", walkErr
	}
	if len(hits) == 0 {
		return "(no matches)", nil
	}
	sort.Strings(hits)
	return strings.Join(hits, "\n"), nil
}
