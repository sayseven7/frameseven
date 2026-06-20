package engagement

import (
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// BuildReport assembles a consolidated, triaged report from the engagement
// store. False positives are excluded from the findings body and listed in an
// appendix instead; every finding uses its effective severity, so a manual
// override prevails over the scanner severity. Extracted data is collected into
// its own section and, when present, the report is flagged confidential.
func (e *Engagement) BuildReport() report.Report {
	var findings []finding.Finding
	var extracted []report.ExtractedItem
	var falsePositives []report.FalsePositiveItem

	for _, item := range e.Findings {
		if !item.IsOpen() {
			falsePositives = append(falsePositives, report.FalsePositiveItem{
				Title:    item.Title,
				Module:   item.Tool,
				Endpoint: item.Endpoint,
				Reason:   firstNonEmpty(item.TriageReason, "marked as false positive"),
			})

			continue
		}

		findings = append(findings, toReportFinding(item))

		if strings.TrimSpace(item.ExtractedData) != "" {
			extracted = append(extracted, report.ExtractedItem{
				Title:    item.Title,
				Endpoint: item.Endpoint,
				Severity: string(item.SeverityEffective),
				Data:     item.ExtractedData,
			})
		}
	}

	rep := report.New("v1", e.Meta.Target, e.Meta.CreatedAt, time.Since(e.Meta.CreatedAt), recon.Surface{Host: e.Meta.Host}, findings, nil)

	rep.EngagementID = e.Meta.ID
	rep.ExtractedData = extracted
	rep.FalsePositives = falsePositives
	rep.Confidential = len(extracted) > 0

	return rep
}

// toReportFinding converts an engagement finding into the report finding model.
// The effective severity is used, extracted data is mirrored into the evidence,
// and the linked remediation playbook plus references become next steps.
func toReportFinding(item Finding) finding.Finding {
	description := item.Description

	if strings.TrimSpace(item.PoC) != "" {
		description = strings.TrimSpace(description + "\n\nProof of concept:\n" + item.PoC)
	}

	evidence := finding.Evidence{
		Request:   item.Request,
		Response:  item.Response,
		Extracted: firstNonEmpty(item.ExtractedData, item.Evidence),
	}

	return finding.Finding{
		Title:       item.Title,
		Module:      item.Tool,
		Severity:    item.SeverityEffective,
		OWASP:       item.OWASP,
		CWE:         item.CWE,
		CVSS:        item.CVSS,
		Description: description,
		Evidence:    evidence,
		NextSteps:   nextSteps(item),
	}
}

func nextSteps(item Finding) []string {
	var steps []string

	if item.RelatedSkill != "" {
		steps = append(steps, "Remediation playbook: "+item.RelatedSkill)
	}

	for _, reference := range item.References {
		if strings.TrimSpace(reference) != "" {
			steps = append(steps, "Reference: "+reference)
		}
	}

	return steps
}
