package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

func writeTools(output io.Writer) {
	fmt.Fprintln(output, "Framework tools v1")

	for _, tool := range scanner.Tools {
		fmt.Fprintf(output, "  %-10s %s\n", tool.Name, tool.Description)
	}
}

func parseToolList(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "default") {
		return scanner.NormalizeTools(nil)
	}

	if strings.EqualFold(value, "all") {
		return scanner.NormalizeTools(scanner.ToolNames())
	}

	byName := map[string]string{}
	for i, tool := range scanner.Tools {
		byName[tool.Name] = tool.Name
		byName[strconv.Itoa(i+1)] = tool.Name
	}

	seen := map[string]bool{}
	var selected []string

	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	}) {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}

		name, ok := byName[part]
		if !ok {
			return nil, fmt.Errorf("unknown scanner tool %q", part)
		}

		if !seen[name] {
			seen[name] = true
			selected = append(selected, name)
		}
	}

	if len(selected) == 0 {
		return nil, errors.New("at least one scanner tool must be selected")
	}

	return scanner.NormalizeTools(selected)
}
