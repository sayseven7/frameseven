package mcp

import (
	"context"
	"errors"
	"os"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/engagement"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
)

// engagementsBaseDir is where engagement stores are persisted. The operator can
// override it; otherwise stores live under ./engagements in the working
// directory, matching the documented layout.
func engagementsBaseDir() string {
	if value := strings.TrimSpace(os.Getenv("FRAMESEVEN_ENGAGEMENTS_DIR")); value != "" {
		return value
	}

	return "engagements"
}

type engagementOpenInput struct {
	Target string `json:"target" jsonschema:"authorized HTTP or HTTPS target URL for this engagement"`
}

type engagementOpenOutput struct {
	Version       string `json:"version" jsonschema:"framework version"`
	EngagementID  string `json:"engagement_id" jsonschema:"identifier for the opened engagement store"`
	Target        string `json:"target" jsonschema:"engagement target"`
	Host          string `json:"host" jsonschema:"engagement host"`
	FindingsCount int    `json:"findings_count" jsonschema:"number of findings already stored in this engagement"`
}

// V1EngagementOpen creates or reopens an engagement store for a target.
func V1EngagementOpen(ctx context.Context, req *mcpsdk.CallToolRequest, input engagementOpenInput) (*mcpsdk.CallToolResult, engagementOpenOutput, error) {
	eng, err := engagement.Open(engagementsBaseDir(), input.Target)
	if err != nil {
		return nil, engagementOpenOutput{}, err
	}

	return nil, engagementOpenOutput{
		Version:       "v1",
		EngagementID:  eng.Meta.ID,
		Target:        eng.Meta.Target,
		Host:          eng.Meta.Host,
		FindingsCount: len(eng.Findings),
	}, nil
}

type findingAddInput struct {
	EngagementID  string   `json:"engagement_id" jsonschema:"engagement store id returned by engagement_open"`
	Title         string   `json:"title" jsonschema:"finding title"`
	Severity      string   `json:"severity" jsonschema:"effective severity: INFO, LOW, MEDIUM, HIGH, or CRITICAL"`
	CWE           string   `json:"cwe" jsonschema:"optional CWE identifier such as CWE-89"`
	OWASP         string   `json:"owasp" jsonschema:"optional OWASP category such as A03:2025 - Injection"`
	CVSS          float64  `json:"cvss" jsonschema:"optional CVSS score"`
	Endpoint      string   `json:"endpoint" jsonschema:"affected endpoint or URL"`
	Description   string   `json:"description" jsonschema:"finding description"`
	PoC           string   `json:"poc" jsonschema:"reproduction steps or payload"`
	Evidence      string   `json:"evidence" jsonschema:"supporting evidence text"`
	ExtractedData string   `json:"extracted_data" jsonschema:"dumps, cracked credentials, or exfiltrated file contents; always included in the report"`
	Status        string   `json:"status" jsonschema:"triage status: new, confirmed, false_positive, or needs_review; defaults to confirmed for manual findings"`
	References    []string `json:"references" jsonschema:"optional reference URLs"`
	Tags          []string `json:"tags" jsonschema:"optional tags used to map a remediation playbook"`
	RelatedSkill  string   `json:"related_skill" jsonschema:"optional remediation playbook resource URI; derived from cwe/owasp/tags when empty"`
}

type findingAddOutput struct {
	Version      string `json:"version" jsonschema:"framework version"`
	EngagementID string `json:"engagement_id" jsonschema:"engagement store id"`
	FindingID    string `json:"finding_id" jsonschema:"id of the stored finding"`
	RelatedSkill string `json:"related_skill,omitempty" jsonschema:"remediation playbook resource linked to the finding"`
}

// V1FindingAdd injects a manual finding into an engagement store.
func V1FindingAdd(ctx context.Context, req *mcpsdk.CallToolRequest, input findingAddInput) (*mcpsdk.CallToolResult, findingAddOutput, error) {
	eng, err := engagement.LoadByID(engagementsBaseDir(), input.EngagementID)
	if err != nil {
		return nil, findingAddOutput{}, err
	}

	severity, err := parseSeverity(input.Severity)
	if err != nil {
		return nil, findingAddOutput{}, err
	}

	status, err := parseStatus(input.Status, engagement.StatusConfirmed)
	if err != nil {
		return nil, findingAddOutput{}, err
	}

	item := engagement.Finding{
		Source:            engagement.SourceManual,
		Tool:              "manual",
		Title:             input.Title,
		Description:       input.Description,
		SeverityEffective: severity,
		CVSS:              input.CVSS,
		CWE:               input.CWE,
		OWASP:             input.OWASP,
		Endpoint:          input.Endpoint,
		PoC:               input.PoC,
		Evidence:          input.Evidence,
		ExtractedData:     input.ExtractedData,
		Status:            status,
		RelatedSkill:      input.RelatedSkill,
		References:        input.References,
		Tags:              input.Tags,
	}

	id, err := eng.Add(item)
	if err != nil {
		return nil, findingAddOutput{}, err
	}

	stored, _ := eng.Find(id)

	return nil, findingAddOutput{
		Version:      "v1",
		EngagementID: eng.Meta.ID,
		FindingID:    id,
		RelatedSkill: stored.RelatedSkill,
	}, nil
}

type findingUpdateInput struct {
	EngagementID  string   `json:"engagement_id" jsonschema:"engagement store id"`
	FindingID     string   `json:"finding_id" jsonschema:"id of the finding to update"`
	Status        string   `json:"status" jsonschema:"new triage status: new, confirmed, false_positive, or needs_review"`
	Severity      string   `json:"severity" jsonschema:"new effective severity override"`
	TriageReason  string   `json:"triage_reason" jsonschema:"justification for the status or severity change"`
	ExtractedData string   `json:"extracted_data" jsonschema:"dumps or sensitive data to attach to the finding"`
	PoC           string   `json:"poc" jsonschema:"reproduction steps or payload to attach"`
	Description   string   `json:"description" jsonschema:"replacement description"`
	RelatedSkill  string   `json:"related_skill" jsonschema:"remediation playbook resource URI"`
	References    []string `json:"references" jsonschema:"replacement reference URLs"`
	Tags          []string `json:"tags" jsonschema:"replacement tags"`
}

type findingUpdateOutput struct {
	Version           string `json:"version" jsonschema:"framework version"`
	EngagementID      string `json:"engagement_id" jsonschema:"engagement store id"`
	FindingID         string `json:"finding_id" jsonschema:"id of the updated finding"`
	Status            string `json:"status" jsonschema:"current triage status"`
	SeverityEffective string `json:"severity_effective" jsonschema:"current effective severity"`
}

// V1FindingUpdate patches an existing finding: status, severity override,
// attached extracted data, and more.
func V1FindingUpdate(ctx context.Context, req *mcpsdk.CallToolRequest, input findingUpdateInput) (*mcpsdk.CallToolResult, findingUpdateOutput, error) {
	eng, err := engagement.LoadByID(engagementsBaseDir(), input.EngagementID)
	if err != nil {
		return nil, findingUpdateOutput{}, err
	}

	patch := engagement.Patch{
		TriageReason:  input.TriageReason,
		ExtractedData: input.ExtractedData,
		PoC:           input.PoC,
		Description:   input.Description,
		RelatedSkill:  input.RelatedSkill,
		References:    input.References,
		Tags:          input.Tags,
	}

	if strings.TrimSpace(input.Status) != "" {
		status, err := parseStatus(input.Status, "")
		if err != nil {
			return nil, findingUpdateOutput{}, err
		}

		patch.Status = status
	}

	if strings.TrimSpace(input.Severity) != "" {
		severity, err := parseSeverity(input.Severity)
		if err != nil {
			return nil, findingUpdateOutput{}, err
		}

		patch.Severity = severity
	}

	if err := eng.Update(input.FindingID, patch); err != nil {
		return nil, findingUpdateOutput{}, err
	}

	stored, _ := eng.Find(input.FindingID)

	return nil, findingUpdateOutput{
		Version:           "v1",
		EngagementID:      eng.Meta.ID,
		FindingID:         input.FindingID,
		Status:            string(stored.Status),
		SeverityEffective: string(stored.SeverityEffective),
	}, nil
}

type triageOverrideInput struct {
	FindingID string `json:"finding_id" jsonschema:"id of the finding to triage"`
	Status    string `json:"status" jsonschema:"triage status: confirmed, false_positive, or needs_review"`
	Reason    string `json:"reason" jsonschema:"justification for the decision"`
}

type triageInput struct {
	EngagementID string                `json:"engagement_id" jsonschema:"engagement store id"`
	Auto         bool                  `json:"auto" jsonschema:"apply automatic false-positive heuristics such as SPA index.html detection"`
	Overrides    []triageOverrideInput `json:"overrides" jsonschema:"manual triage decisions applied after the automatic pass"`
}

type triageOutput struct {
	Version            string `json:"version" jsonschema:"framework version"`
	EngagementID       string `json:"engagement_id" jsonschema:"engagement store id"`
	AutoFalsePositives int    `json:"auto_false_positives" jsonschema:"findings auto-flagged as false positives"`
	Confirmed          int    `json:"confirmed" jsonschema:"findings marked confirmed"`
	FalsePositives     int    `json:"false_positives" jsonschema:"total findings marked false positive"`
	NeedsReview        int    `json:"needs_review" jsonschema:"findings marked needs review"`
	OpenFindings       int    `json:"open_findings" jsonschema:"findings kept in the report body"`
}

// V1Triage runs automatic false-positive heuristics and manual overrides.
func V1Triage(ctx context.Context, req *mcpsdk.CallToolRequest, input triageInput) (*mcpsdk.CallToolResult, triageOutput, error) {
	eng, err := engagement.LoadByID(engagementsBaseDir(), input.EngagementID)
	if err != nil {
		return nil, triageOutput{}, err
	}

	overrides := make([]engagement.Override, 0, len(input.Overrides))
	for _, override := range input.Overrides {
		status, err := parseStatus(override.Status, "")
		if err != nil {
			return nil, triageOutput{}, err
		}

		overrides = append(overrides, engagement.Override{
			FindingID: override.FindingID,
			Status:    status,
			Reason:    override.Reason,
		})
	}

	result, err := eng.Triage(input.Auto, overrides)
	if err != nil {
		return nil, triageOutput{}, err
	}

	return nil, triageOutput{
		Version:            "v1",
		EngagementID:       eng.Meta.ID,
		AutoFalsePositives: result.AutoFalsePositives,
		Confirmed:          result.Confirmed,
		FalsePositives:     result.FalsePositives,
		NeedsReview:        result.NeedsReview,
		OpenFindings:       result.Open,
	}, nil
}

type reportEngagementInput struct {
	EngagementID string `json:"engagement_id" jsonschema:"engagement store id"`
	Format       string `json:"format" jsonschema:"report format: text, markdown, html, pdf, both, or all; defaults to text"`
}

// V1ReportEngagement renders the consolidated, triaged engagement report.
func V1ReportEngagement(ctx context.Context, req *mcpsdk.CallToolRequest, input reportEngagementInput) (*mcpsdk.CallToolResult, reportToolOutput, error) {
	format, err := normalizeReportFormat(input.Format)
	if err != nil {
		return nil, reportToolOutput{}, err
	}

	eng, err := engagement.LoadByID(engagementsBaseDir(), input.EngagementID)
	if err != nil {
		return nil, reportToolOutput{}, err
	}

	rep := eng.BuildReport()

	out, err := buildReportToolOutput(nil, format, rep, false)
	if err != nil {
		return nil, reportToolOutput{}, err
	}

	out.EngagementID = eng.Meta.ID

	return nil, out, nil
}

// appendToEngagement appends scan findings to an engagement store when the
// caller supplied an engagement id. A missing store is not a hard error: the
// scan result is still returned. It reports the resolved engagement id.
func appendToEngagement(engagementID, target string, rep report.Report) string {
	engagementID = strings.TrimSpace(engagementID)
	if engagementID == "" {
		return ""
	}

	eng, err := engagement.LoadByID(engagementsBaseDir(), engagementID)
	if err != nil {
		eng, err = engagement.Open(engagementsBaseDir(), target)
		if err != nil {
			return ""
		}
	}

	if err := eng.SetSurface(rep.Surface); err != nil {
		return eng.Meta.ID
	}

	byTool := map[string][]finding.Finding{}
	for _, item := range rep.Findings {
		byTool[item.Module] = append(byTool[item.Module], item)
	}

	for tool, findings := range byTool {
		if _, err := eng.AddScanFindings(tool, findings); err != nil {
			return eng.Meta.ID
		}
	}

	return eng.Meta.ID
}

func parseSeverity(value string) (finding.Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", string(finding.Info):
		return finding.Info, nil
	case string(finding.Low):
		return finding.Low, nil
	case string(finding.Medium):
		return finding.Medium, nil
	case string(finding.High):
		return finding.High, nil
	case string(finding.Critical):
		return finding.Critical, nil
	default:
		return "", errors.New("severity must be one of INFO, LOW, MEDIUM, HIGH, CRITICAL")
	}
}

func parseStatus(value string, fallback engagement.Status) (engagement.Status, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return fallback, nil
	case string(engagement.StatusNew):
		return engagement.StatusNew, nil
	case string(engagement.StatusConfirmed):
		return engagement.StatusConfirmed, nil
	case string(engagement.StatusFalsePositive), "fp", "false-positive":
		return engagement.StatusFalsePositive, nil
	case string(engagement.StatusNeedsReview), "review", "needs-review":
		return engagement.StatusNeedsReview, nil
	default:
		return "", errors.New("status must be one of new, confirmed, false_positive, needs_review")
	}
}
