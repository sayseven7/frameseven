package mcp

import (
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

var (
	destructiveHint = true
	readOnlyHint    = true
	idempotentHint  = true
)

// RegisterTools adds the FrameSeven MCP tools.
func RegisterTools(server *mcpsdk.Server) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_list_tools",
		Title:       "List Scanner Tools",
		Description: "List Framework v1 scanner tools and whether each tool runs by default.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:   readOnlyHint,
			IdempotentHint: idempotentHint,
		},
	}, V1ListTools)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_normalize_tools",
		Title:       "Normalize Tool Selection",
		Description: "Validate and normalize a Framework v1 tool selection without starting a scan.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:   readOnlyHint,
			IdempotentHint: idempotentHint,
		},
	}, V1NormalizeTools)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_report",
		Title:       "Run Scan and Render CLI Report",
		Description: "Run Framework v1 scanner tools and return the result rendered as text, Markdown, HTML, PDF, or all report formats. Pass auth_cookies and/or auth_headers (and optional seed_endpoints) to run the scan as an authenticated session.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: &destructiveHint,
		},
	}, V1Report)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_engagement_open",
		Title:       "Open Engagement Store",
		Description: "Create or reopen a persistent engagement store for a target. Scanner findings and manual findings are accumulated here for triage and a consolidated report.",
		Annotations: &mcpsdk.ToolAnnotations{
			IdempotentHint: idempotentHint,
		},
	}, V1EngagementOpen)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_finding_add",
		Title:       "Add Manual Finding",
		Description: "Inject a manual finding into an engagement store, including extracted_data (dumps, cracked credentials, exfiltrated files) which is always included in the report.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: &destructiveHint,
		},
	}, V1FindingAdd)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_finding_update",
		Title:       "Update Finding",
		Description: "Patch a stored finding: change triage status, override severity, or attach extracted data and proof without losing the original scanner evidence.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: &destructiveHint,
		},
	}, V1FindingUpdate)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_triage",
		Title:       "Triage Findings",
		Description: "Run automatic false-positive heuristics (such as SPA index.html catch-all detection) and apply manual triage overrides to an engagement store.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: &destructiveHint,
		},
	}, V1Triage)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_finding_list",
		Title:       "List Engagement Findings",
		Description: "List findings stored in an engagement with optional filters by status, tool, and minimum confidence. Returns finding IDs that can be used with finding_update or triage.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:   readOnlyHint,
			IdempotentHint: idempotentHint,
		},
	}, V1FindingList)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "frameseven_v1_report_engagement",
		Title:       "Render Engagement Report",
		Description: "Render the consolidated, triaged engagement report as text, Markdown, HTML, PDF, or all formats. False positives are excluded from the body and listed in an appendix; extracted data gets its own section.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint: readOnlyHint,
		},
	}, V1ReportEngagement)

	for _, tool := range scanner.Tools {
		scanTool := tool
		mcpsdk.AddTool(server, &mcpsdk.Tool{
			Name:        "frameseven_v1_" + scanTool.Name,
			Title:       "Run " + scanTool.Name + " Scanner Tool",
			Description: "Run the Framework v1 " + scanTool.Name + " tool. " + scanTool.Description + "." + scanToolDirective(scanTool.Name) + " Pass auth_cookies and/or auth_headers (and optional seed_endpoints) to run authenticated.",
			Annotations: &mcpsdk.ToolAnnotations{
				DestructiveHint: &destructiveHint,
			},
		}, V1ScanTool(scanTool.Name))
	}
}
