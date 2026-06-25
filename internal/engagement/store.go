package engagement

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const (
	metaFile     = "meta.json"
	findingsFile = "findings.jsonl"
)

// Engagement is an open assessment store. It is loaded fully into memory and
// rewritten to disk on every mutation, which keeps the on-disk files simple
// (one JSON meta file plus one finding per line in findings.jsonl).
type Engagement struct {
	Meta     Meta
	Findings []Finding

	dir string
}

// Open creates or reopens the engagement store for a target under baseDir. The
// engagement id is derived from the target host plus a short hash of the target,
// so reopening the same target returns the same store and appended findings
// deduplicate across runs.
func Open(baseDir, target string) (*Engagement, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target is required")
	}

	host := targetHost(target)
	id := host + "-" + shortHash(target, 8)
	dir := filepath.Join(baseDir, id)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create engagement directory: %w", err)
	}

	eng := &Engagement{dir: dir}

	if err := eng.load(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	if eng.Meta.ID == "" {
		eng.Meta = Meta{
			ID:        id,
			Target:    target,
			Host:      host,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}

	if err := eng.save(); err != nil {
		return nil, err
	}

	return eng, nil
}

// LoadByID reopens an existing engagement by its id under baseDir.
func LoadByID(baseDir, id string) (*Engagement, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("engagement id is required")
	}

	dir := filepath.Join(baseDir, filepath.Base(id))

	if _, err := os.Stat(filepath.Join(dir, metaFile)); err != nil {
		return nil, fmt.Errorf("engagement %q not found", id)
	}

	eng := &Engagement{dir: dir}

	if err := eng.load(); err != nil {
		return nil, err
	}

	return eng, nil
}

// AddScanFindings converts and appends scanner findings to the store. Findings
// that already exist (same signature) are not duplicated; their occurrence
// counter is incremented instead. It returns all resulting finding ids (newly
// stored plus updated via merge). Scanner findings are born with confidence 0.0
// and are elevated later by the anti-false-positive verifiers.
func (e *Engagement) AddScanFindings(tool string, scanFindings []finding.Finding) ([]string, error) {
	var ids []string

	for _, sf := range scanFindings {
		item := Finding{
			Source:            SourceScanner,
			Tool:              firstNonEmpty(sf.Module, tool),
			Title:             sf.Title,
			Description:       sf.Description,
			SeverityScanner:   sf.Severity,
			SeverityEffective: sf.Severity,
			CVSS:              sf.CVSS,
			CWE:               sf.CWE,
			OWASP:             sf.OWASP,
			Request:           sf.Evidence.Request,
			Response:          sf.Evidence.Response,
			Evidence:          sf.Evidence.Extracted,
			Status:            StatusNew,
		}

		if id, _ := e.upsert(item); id != "" {
			ids = append(ids, id)
		}
	}

	if err := e.save(); err != nil {
		return nil, err
	}

	return ids, nil
}

// Add stores a single finding (typically manual) and returns its id. Like
// AddScanFindings it deduplicates by signature.
func (e *Engagement) Add(item Finding) (string, error) {
	if strings.TrimSpace(item.Title) == "" {
		return "", errors.New("finding title is required")
	}

	if item.Source == "" {
		item.Source = SourceManual
	}

	if item.SeverityEffective == "" {
		item.SeverityEffective = finding.Info
	}

	if item.Status == "" {
		item.Status = StatusNew
	}

	// Default confidence based on status
	if item.Confidence == 0 {
		switch item.Status {
		case StatusConfirmed:
			item.Confidence = DefaultConfidenceConfirmed
		case StatusNeedsReview:
			item.Confidence = DefaultConfidenceNeedsReview
		}
	}

	id, _ := e.upsert(item)

	if err := e.save(); err != nil {
		return "", err
	}

	return id, nil
}

// Patch holds the optional fields a finding update may change. Empty fields are
// left untouched.
type Patch struct {
	Status        Status
	Severity      finding.Severity
	TriageReason  string
	ExtractedData string
	PoC           string
	Description   string
	RelatedSkill  string
	References    []string
	Tags          []string
}

// Update applies a patch to the finding with the given id.
func (e *Engagement) Update(id string, patch Patch) error {
	index := e.indexByID(id)
	if index < 0 {
		return fmt.Errorf("finding %q not found", id)
	}

	item := &e.Findings[index]

	if patch.Status != "" {
		item.Status = patch.Status
	}

	if patch.Severity != "" {
		item.SeverityEffective = patch.Severity
	}

	if patch.TriageReason != "" {
		item.TriageReason = patch.TriageReason
	}

	if patch.ExtractedData != "" {
		item.ExtractedData = patch.ExtractedData
	}

	if patch.PoC != "" {
		item.PoC = patch.PoC
	}

	if patch.Description != "" {
		item.Description = patch.Description
	}

	if patch.RelatedSkill != "" {
		item.RelatedSkill = patch.RelatedSkill
	}

	if len(patch.References) > 0 {
		item.References = patch.References
	}

	if len(patch.Tags) > 0 {
		item.Tags = patch.Tags
	}

	item.UpdatedAt = time.Now().UTC()

	return e.save()
}

// SetSurface persists the attack surface mapped during a scan into the
// engagement meta, so reports built from this store reflect the same scope
// information the scanner observed.
//
// Surfaces are merged per field rather than replaced wholesale: the most recent
// scan wins for every field it actually mapped, but a field the new scan left
// empty keeps whatever a previous scan found. This matters because a single
// engagement is built from several scan calls and only the offensive tools pull
// in recon; a later misconfig/ports/nmap scan reports an empty surface and must
// not wipe the technologies, endpoints, parameters, and sensitive files an
// earlier recon scan already discovered.
func (e *Engagement) SetSurface(surface recon.Surface) error {
	e.Meta.Surface = mergeSurface(e.Meta.Surface, surface)
	return e.save()
}

// mergeSurface overlays the next surface onto the current one, keeping the
// current value for any field the next surface left empty.
func mergeSurface(current, next recon.Surface) recon.Surface {
	if next.BaseURL != "" {
		current.BaseURL = next.BaseURL
	}

	if next.Host != "" {
		current.Host = next.Host
	}

	if len(next.Headers) > 0 {
		current.Headers = next.Headers
	}

	if len(next.Technologies) > 0 {
		current.Technologies = next.Technologies
	}

	if len(next.DNS.A) > 0 || next.DNS.CNAME != "" || len(next.DNS.MX) > 0 || len(next.DNS.NS) > 0 || len(next.DNS.TXT) > 0 {
		current.DNS = next.DNS
	}

	if len(next.Endpoints) > 0 {
		current.Endpoints = next.Endpoints
	}

	if len(next.Params) > 0 {
		current.Params = next.Params
	}

	if len(next.SensitiveFiles) > 0 {
		current.SensitiveFiles = next.SensitiveFiles
	}

	return current
}

// Find returns the finding with the given id, or false when it does not exist.
func (e *Engagement) Find(id string) (Finding, bool) {
	index := e.indexByID(id)
	if index < 0 {
		return Finding{}, false
	}

	return e.Findings[index], true
}

// upsert inserts a finding or merges it into an existing one with the same
// signature. It returns the finding id and whether a new finding was created.
func (e *Engagement) upsert(item Finding) (string, bool) {
	signature := item.signature()

	for i := range e.Findings {
		if e.Findings[i].signature() != signature {
			continue
		}

		existing := &e.Findings[i]
		existing.Occurrences++
		existing.UpdatedAt = time.Now().UTC()

		mergeInto(existing, item)

		return existing.ID, false
	}

	now := time.Now().UTC()

	item.ID = shortHash(e.Meta.ID+"\n"+signature, 12)
	item.EngagementID = e.Meta.ID
	item.CreatedAt = now
	item.UpdatedAt = now
	item.Occurrences = 1

	if item.RelatedSkill == "" {
		item.RelatedSkill = SkillFor(item.CWE, item.OWASP, item.Tags)
	}

	e.Findings = append(e.Findings, item)

	return item.ID, true
}

// mergeInto enriches an existing finding with non-empty values from a newer
// one. It never lowers an already stored effective severity and preserves the
// original scanner evidence while adding manual proof and extracted data.
func mergeInto(existing *Finding, item Finding) {
	if item.ExtractedData != "" {
		existing.ExtractedData = item.ExtractedData
	}

	if item.PoC != "" {
		existing.PoC = item.PoC
	}

	if item.Request != "" && existing.Request == "" {
		existing.Request = item.Request
	}

	if item.Response != "" && existing.Response == "" {
		existing.Response = item.Response
	}

	if item.SeverityEffective.Rank() > existing.SeverityEffective.Rank() {
		existing.SeverityEffective = item.SeverityEffective
	}

	if item.RelatedSkill != "" {
		existing.RelatedSkill = item.RelatedSkill
	}

	if item.Source == SourceManual {
		existing.Source = SourceManual
	}
}

func (e *Engagement) indexByID(id string) int {
	id = strings.TrimSpace(id)
	for i := range e.Findings {
		if e.Findings[i].ID == id {
			return i
		}
	}

	return -1
}

func (e *Engagement) load() error {
	metaPath := filepath.Join(e.dir, metaFile)

	data, err := os.ReadFile(metaPath) // #nosec G304 - the operator selects the engagement directory
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("read engagement meta: %w", err)
	}

	if err := json.Unmarshal(data, &e.Meta); err != nil {
		return fmt.Errorf("decode engagement meta: %w", err)
	}

	return e.loadFindings()
}

func (e *Engagement) loadFindings() error {
	path := filepath.Join(e.dir, findingsFile)

	file, err := os.Open(path) // #nosec G304 - the operator selects the engagement directory
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("read engagement findings: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var item Finding
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return fmt.Errorf("decode engagement finding: %w", err)
		}

		e.Findings = append(e.Findings, item)
	}

	return scanner.Err()
}

func (e *Engagement) save() error {
	e.Meta.UpdatedAt = time.Now().UTC()

	metaData, err := json.MarshalIndent(e.Meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode engagement meta: %w", err)
	}

	if err := os.WriteFile(filepath.Join(e.dir, metaFile), metaData, 0600); err != nil { // #nosec G304 - the operator selects the engagement directory
		return fmt.Errorf("write engagement meta: %w", err)
	}

	var b strings.Builder
	for _, item := range e.Findings {
		line, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("encode engagement finding: %w", err)
		}

		b.Write(line)
		b.WriteByte('\n')
	}

	if err := os.WriteFile(filepath.Join(e.dir, findingsFile), []byte(b.String()), 0600); err != nil { // #nosec G304 - the operator selects the engagement directory
		return fmt.Errorf("write engagement findings: %w", err)
	}

	return nil
}

func targetHost(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return sanitizeHost(target)
	}

	return sanitizeHost(u.Hostname())
}

func sanitizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))

	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}

	host := strings.Trim(b.String(), "-.")
	if host == "" {
		return "target"
	}

	return host
}

func shortHash(value string, length int) string {
	sum := sha256.Sum256([]byte(value))
	hexed := hex.EncodeToString(sum[:])

	if length > len(hexed) {
		length = len(hexed)
	}

	return hexed[:length]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}
