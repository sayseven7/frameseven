package mcp

import (
	"strings"
	"testing"

	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

func TestSkillURIForToolKnownAndFallback(t *testing.T) {
	uri := skillURIForTool("sqli")
	if uri != skillURIPrefix+"sqli-sql-injection/SKILL.md" {
		t.Errorf("skillURIForTool(sqli) = %q", uri)
	}

	fallback := skillURIForTool("unknown-tool")
	if fallback != skillURIPrefix+fallbackSkill+"/SKILL.md" {
		t.Errorf("skillURIForTool(unknown) = %q, want fallback", fallback)
	}
}

// TestEveryScannerToolMapsToAnEmbeddedSkill guards against typos and skill
// directory drift: every scanner tool must resolve to a SKILL.md that exists in
// the embedded playbooks.
func TestEveryScannerToolMapsToAnEmbeddedSkill(t *testing.T) {
	for _, tool := range scanner.Tools {
		uri := skillURIForTool(tool.Name)
		rel := strings.TrimPrefix(uri, skillURIPrefix)
		embedPath := skillsRoot + "/" + rel

		if _, err := skillsFS.ReadFile(embedPath); err != nil {
			t.Errorf("tool %q maps to missing skill %q: %v", tool.Name, embedPath, err)
		}
	}
}

func TestScanToolDirectiveReferencesSkill(t *testing.T) {
	directive := scanToolDirective("xss")

	if !strings.Contains(directive, skillURIForTool("xss")) {
		t.Errorf("directive missing skill URI: %q", directive)
	}

	if !strings.Contains(directive, "finding_add") {
		t.Errorf("directive missing finding_add mandate: %q", directive)
	}
}

func TestScanGuidanceReferencesSkill(t *testing.T) {
	guidance := scanGuidance("cmdi")

	if !strings.Contains(guidance, skillURIForTool("cmdi")) {
		t.Errorf("guidance missing skill URI: %q", guidance)
	}

	if !strings.Contains(guidance, "FrameSeven does not scan") {
		t.Errorf("guidance missing coverage-gap nudge: %q", guidance)
	}
}

func TestBuildScanToolOutputSetsGuidance(t *testing.T) {
	output := buildScanToolOutput("sqli", []string{"sqli"}, reportFixture(), false, "")

	if output.Guidance != scanGuidance("sqli") {
		t.Errorf("guidance = %q, want %q", output.Guidance, scanGuidance("sqli"))
	}
}
