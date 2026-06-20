package engagement

import "strings"

// skillURIPrefix mirrors the resource prefix used by the MCP server so report
// remediation links point at a readable playbook resource.
const skillURIPrefix = "skill://hack-skills/v1/"

// skillByCWE maps a CWE identifier to the hack-skills playbook directory that
// best documents that class of issue.
var skillByCWE = map[string]string{
	"CWE-89":   "sqli-sql-injection",
	"CWE-78":   "cmdi-command-injection",
	"CWE-79":   "xss-cross-site-scripting",
	"CWE-22":   "path-traversal-lfi",
	"CWE-98":   "path-traversal-lfi",
	"CWE-918":  "ssrf-server-side-request-forgery",
	"CWE-639":  "idor-broken-object-authorization",
	"CWE-862":  "idor-broken-object-authorization",
	"CWE-863":  "idor-broken-object-authorization",
	"CWE-287":  "authbypass-authentication-flaws",
	"CWE-352":  "csrf-cross-site-request-forgery",
	"CWE-611":  "xxe-xml-external-entity",
	"CWE-502":  "deserialization-insecure",
	"CWE-1336": "ssti-server-side-template-injection",
	"CWE-200":  "recon-and-methodology",
	"CWE-538":  "file-access-vuln",
	"CWE-16":   "recon-and-methodology",
	"CWE-521":  "hash-attack-techniques",
	"CWE-916":  "hash-attack-techniques",
}

// skillByTag maps a finding tag keyword to a playbook directory.
var skillByTag = map[string]string{
	"sqli":       "sqli-sql-injection",
	"sql":        "sqli-sql-injection",
	"dump":       "sqli-sql-injection",
	"idor":       "idor-broken-object-authorization",
	"ssrf":       "ssrf-server-side-request-forgery",
	"lfi":        "path-traversal-lfi",
	"traversal":  "path-traversal-lfi",
	"xss":        "xss-cross-site-scripting",
	"auth":       "authbypass-authentication-flaws",
	"takeover":   "authbypass-authentication-flaws",
	"credential": "hash-attack-techniques",
	"hash":       "hash-attack-techniques",
	"password":   "hash-attack-techniques",
	"upload":     "upload-insecure-files",
	"xxe":        "xxe-xml-external-entity",
	"ssti":       "ssti-server-side-template-injection",
	"cmdi":       "cmdi-command-injection",
	"rce":        "cmdi-command-injection",
}

// skillByOWASP maps an OWASP category prefix to a playbook directory.
var skillByOWASP = map[string]string{
	"a01": "idor-broken-object-authorization",
	"a02": "hash-attack-techniques",
	"a03": "sqli-sql-injection",
	"a07": "authbypass-authentication-flaws",
	"a10": "ssrf-server-side-request-forgery",
}

// SkillFor returns the remediation playbook resource URI for a finding based on
// its CWE, OWASP category, or tags. It returns an empty string when no mapping
// applies.
func SkillFor(cwe, owasp string, tags []string) string {
	if dir := skillByCWE[strings.ToUpper(strings.TrimSpace(cwe))]; dir != "" {
		return skillURIPrefix + dir + "/SKILL.md"
	}

	for _, tag := range tags {
		if dir := skillByTag[strings.ToLower(strings.TrimSpace(tag))]; dir != "" {
			return skillURIPrefix + dir + "/SKILL.md"
		}
	}

	if dir := skillByOWASP[owaspPrefix(owasp)]; dir != "" {
		return skillURIPrefix + dir + "/SKILL.md"
	}

	return ""
}

// owaspPrefix extracts the leading "aNN" token from an OWASP category string
// such as "A03:2025 - Injection".
func owaspPrefix(owasp string) string {
	owasp = strings.ToLower(strings.TrimSpace(owasp))
	if len(owasp) < 3 {
		return ""
	}

	if owasp[0] != 'a' {
		return ""
	}

	return owasp[:3]
}
