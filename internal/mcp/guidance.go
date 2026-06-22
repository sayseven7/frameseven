package mcp

// toolSkills maps each Framework v1 scanner tool to the hack-skills playbook an
// agent should read before running it and apply when exploiting its findings.
// Tools without a dedicated playbook fall back to the recon methodology skill.
var toolSkills = map[string]string{
	"recon":      "recon-and-methodology",
	"sqli":       "sqli-sql-injection",
	"sqlmap":     "sqli-sql-injection",
	"access":     "idor-broken-object-authorization",
	"ssrf":       "ssrf-server-side-request-forgery",
	"lfi":        "path-traversal-lfi",
	"xss":        "xss-cross-site-scripting",
	"xxe":        "xxe-xml-external-entity",
	"cmdi":       "cmdi-command-injection",
	"ssti":       "ssti-server-side-template-injection",
	"redirect":   "open-redirect",
	"authtest":   "authbypass-authentication-flaws",
	"misconfig":  "cors-cross-origin-misconfiguration",
	"subdomain":  "subdomain-takeover",
	"bannergrab": "unauthorized-access-common-services",
	"crawler":    "recon-and-methodology",
	"content":    "recon-and-methodology",
	"ports":      "recon-and-methodology",
	"nmap":       "recon-and-methodology",
}

const fallbackSkill = "recon-and-methodology"

// skillURIForTool returns the skill resource URI an agent should read before
// running the given scanner tool.
func skillURIForTool(name string) string {
	skill := toolSkills[name]

	if skill == "" {
		skill = fallbackSkill
	}

	return skillURIPrefix + skill + "/SKILL.md"
}

// scanToolDirective is the layer-1 instruction appended to every scanner tool
// description so the mandate to study the skill and exploit deeply is in context
// at the moment the agent decides to call the tool.
func scanToolDirective(name string) string {
	return " Before calling, read " + skillURIForTool(name) + " and apply its methodology. " +
		"On a positive result, do not stop at detection: exploit to the maximum depth the active " +
		"scan authorization allows, extracting sensitive data and confirming RCE where the skill " +
		"describes it, then record the proof and any extracted_data with finding_add."
}

// scanGuidance is the layer-2 reminder returned in every scanner result so the
// agent is nudged toward deeper exploitation right when it reads the output.
func scanGuidance(name string) string {
	return "Detection is only the start. Read " + skillURIForTool(name) + " and exploit each " +
		"finding to the maximum depth the active scan authorization allows: extract sensitive data " +
		"and confirm RCE where applicable, then record the proof and any extracted_data with " +
		"finding_add. Also probe for vulnerability classes FrameSeven does not scan, such as nosql, " +
		"graphql, jwt, deserialization, race-condition, and request-smuggling, using the matching " +
		"skill:// playbooks."
}
