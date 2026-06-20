package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteMarkdown renders a portable, human-readable report.
func WriteMarkdown(w io.Writer, rep Report) error {
	fmt.Fprintln(w, "# frameseven Scan Report")
	fmt.Fprintln(w)

	if rep.Confidential {
		fmt.Fprintln(w, "> **CONFIDENTIAL** — this report contains extracted sensitive data. Handle and store securely.")
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "- **Target:** `%s`\n", rep.Target)

	if rep.EngagementID != "" {
		fmt.Fprintf(w, "- **Engagement:** `%s`\n", rep.EngagementID)
	}

	fmt.Fprintf(w, "- **Started:** `%s`\n", rep.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "- **Duration:** `%s`\n", rep.Duration)
	fmt.Fprintf(w, "- **Status:** `%s`\n", reportStatus(rep))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Findings: **%d**\n", len(rep.Findings))
	fmt.Fprintf(w, "- %s\n", strings.TrimSpace(countsBySeverity(rep.Findings)))
	fmt.Fprintf(w, "- Tool errors: **%d**\n", len(rep.Errors))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Attack Surface")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Host: `%s`\n", rep.Surface.Host)
	fmt.Fprintf(w, "- Technologies: **%d**\n", len(rep.Surface.Technologies))
	fmt.Fprintf(w, "- Endpoints: **%d**\n", len(rep.Surface.Endpoints))
	fmt.Fprintf(w, "- Parameters: **%d**\n", len(rep.Surface.Params))
	fmt.Fprintf(w, "- Sensitive files: **%d**\n", len(rep.Surface.SensitiveFiles))
	fmt.Fprintln(w)

	if len(rep.Errors) > 0 {
		fmt.Fprintln(w, "## Scan Errors")
		fmt.Fprintln(w)

		for _, scanErr := range rep.Errors {
			fmt.Fprintf(w, "- **%s:** %s\n", scanErr.Module, scanErr.Message)
		}

		fmt.Fprintln(w)
	}

	writeMarkdownExtractedData(w, rep.ExtractedData)

	fmt.Fprintln(w, "## Findings")
	fmt.Fprintln(w)

	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		fmt.Fprintln(w)

		writeMarkdownFalsePositives(w, rep.FalsePositives)

		return nil
	}

	for i, item := range rep.Findings {
		fmt.Fprintf(w, "### %d. [%s] %s\n\n", i+1, item.Severity, item.Title)
		fmt.Fprintf(w, "- **Tool:** `%s`\n", item.Module)

		if item.CVSS > 0 {
			fmt.Fprintf(w, "- **CVSS:** `%.1f`\n", item.CVSS)
		}

		if item.CWE != "" {
			fmt.Fprintf(w, "- **CWE:** `%s`\n", item.CWE)
		}

		if item.OWASP != "" {
			fmt.Fprintf(w, "- **OWASP:** `%s`\n", item.OWASP)
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, item.Description)
		fmt.Fprintln(w)

		writeMarkdownEvidence(w, "Request", item.Evidence.Request)
		writeMarkdownEvidence(w, "Response", item.Evidence.Response)
		writeMarkdownEvidence(w, "Extracted Evidence", item.Evidence.Extracted)

		if len(item.NextSteps) > 0 {
			fmt.Fprintln(w, "#### Next Steps")
			fmt.Fprintln(w)

			for _, step := range item.NextSteps {
				fmt.Fprintf(w, "- %s\n", step)
			}

			fmt.Fprintln(w)
		}
	}

	writeMarkdownFalsePositives(w, rep.FalsePositives)

	return nil
}

func writeMarkdownExtractedData(w io.Writer, items []ExtractedItem) {
	if len(items) == 0 {
		return
	}

	fmt.Fprintln(w, "## Sensitive Data Extracted")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Data recovered during exploitation. Treat every value below as a confirmed exposure.")
	fmt.Fprintln(w)

	for _, item := range items {
		fmt.Fprintf(w, "### %s\n\n", item.Title)

		if item.Severity != "" {
			fmt.Fprintf(w, "- **Severity:** `%s`\n", item.Severity)
		}

		if item.Endpoint != "" {
			fmt.Fprintf(w, "- **Endpoint:** `%s`\n", item.Endpoint)
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, "```text")
		fmt.Fprintln(w, item.Data)
		fmt.Fprintln(w, "```")
		fmt.Fprintln(w)
	}
}

func writeMarkdownFalsePositives(w io.Writer, items []FalsePositiveItem) {
	if len(items) == 0 {
		return
	}

	fmt.Fprintln(w, "## Appendix: Discarded False Positives")
	fmt.Fprintln(w)

	for _, item := range items {
		fmt.Fprintf(w, "- **%s**", item.Title)

		if item.Module != "" {
			fmt.Fprintf(w, " `%s`", item.Module)
		}

		if item.Endpoint != "" {
			fmt.Fprintf(w, " — `%s`", item.Endpoint)
		}

		if item.Reason != "" {
			fmt.Fprintf(w, " — %s", item.Reason)
		}

		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
}

func writeMarkdownEvidence(w io.Writer, title, value string) {
	if value == "" {
		return
	}

	fmt.Fprintf(w, "#### %s\n\n", title)
	fmt.Fprintln(w, "```text")
	fmt.Fprintln(w, value)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
}

func reportStatus(rep Report) string {
	if len(rep.Errors) > 0 {
		return "incomplete"
	}

	return "complete"
}
