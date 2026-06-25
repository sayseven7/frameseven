package mcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sayseven7/frameseven/internal/engagement"
)

type findingVerifyInput struct {
	EngagementID string `json:"engagement_id" jsonschema:"engagement store id"`
	FindingID    string `json:"finding_id" jsonschema:"id of the finding to re-verify"`
}

type findingVerifyOutput struct {
	EngagementID string  `json:"engagement_id"`
	FindingID    string  `json:"finding_id"`
	Status       string  `json:"status"`
	Confidence   float64 `json:"confidence"`
	Verified     bool    `json:"verified"`
	Detail       string  `json:"detail"`
}

// V1FindingVerify re-executes the proof-of-concept for a stored finding and
// updates its status and confidence based on the current response.
//
// Verification replays the stored raw HTTP request against the target and
// checks whether the original behavior still reproduces: a strong marker from
// the extracted data still appears, or the response still matches the stored
// one.
//
// Findings that pass verification become status=confirmed with confidence
// elevated by 0.2 (capped at 1.0). Failed verification drops confidence by
// 0.2 (floor 0.0) and sets status=needs_review.
func V1FindingVerify(ctx context.Context, req *mcpsdk.CallToolRequest, input findingVerifyInput) (*mcpsdk.CallToolResult, findingVerifyOutput, error) {
	eng, err := engagement.LoadByID(engagementsBaseDir(), input.EngagementID)
	if err != nil {
		return nil, findingVerifyOutput{}, err
	}

	item, ok := eng.Find(input.FindingID)
	if !ok {
		return nil, findingVerifyOutput{}, fmt.Errorf("finding %q not found", input.FindingID)
	}

	verified, detail := verifyFinding(item)

	var patch engagement.Patch
	if verified {
		patch.Status = engagement.StatusConfirmed

		newConf := item.Confidence + 0.2
		if newConf > 1.0 {
			newConf = 1.0
		}

		patch.Confidence = newConf
	} else {
		patch.Status = engagement.StatusNeedsReview

		newConf := item.Confidence - 0.2
		if newConf < 0 {
			newConf = 0
		}

		patch.Confidence = newConf
	}

	patch.TriageReason = detail

	if err := eng.Update(input.FindingID, patch); err != nil {
		return nil, findingVerifyOutput{}, err
	}

	updated, _ := eng.Find(input.FindingID)

	return nil, findingVerifyOutput{
		EngagementID: eng.Meta.ID,
		FindingID:    updated.ID,
		Status:       string(updated.Status),
		Confidence:   updated.Confidence,
		Verified:     verified,
		Detail:       detail,
	}, nil
}

// verifyFinding replays the stored Request and checks whether the original
// behavior reproduces. Returns (verified, detail).
func verifyFinding(item engagement.Finding) (bool, string) {
	if strings.TrimSpace(item.Request) == "" {
		return false, "no request to replay"
	}

	req, err := parseRawHTTPRequest(item.Request)
	if err != nil {
		return false, fmt.Sprintf("failed to parse stored request: %v", err)
	}

	// The dumped request line is relative; recover scheme and host from the
	// finding endpoint so the replay reaches the live target.
	if eu, err := url.Parse(item.Endpoint); err == nil && eu.Host != "" {
		req.URL.Scheme = eu.Scheme
		req.URL.Host = eu.Host
	}

	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("replay failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// 1. A strong marker from the extracted data still present in the response is
	// the most reliable signal the proof reproduces.
	if item.ExtractedData != "" {
		for _, marker := range extractStrongMarkers(item.ExtractedData) {
			if strings.Contains(string(body), marker) {
				return true, "extracted-data marker still present in response"
			}
		}
	}

	// 2. Otherwise the live response must still match the stored response.
	if item.Response != "" {
		if bodyHashTrimmed(item.Response) == bodyHashTrimmed(string(body)) {
			return true, "response identical to stored response"
		}
	}

	return false, "response no longer matches; finding may be patched or transient"
}

// parseRawHTTPRequest parses a raw HTTP request dump into a client-ready request.
func parseRawHTTPRequest(raw string) (*http.Request, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return nil, err
	}

	// RequestURI must be cleared before a parsed server request can be sent by
	// an HTTP client.
	req.RequestURI = ""

	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}

	return req, nil
}

var (
	jwtMarkerRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}`)
	hexHashRe   = regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`)
	quotedRe    = regexp.MustCompile(`'[^']{4,}'`)
	credLineRe  = regexp.MustCompile(`^[A-Za-z0-9._%+@-]+:[^:\s]{3,}`)
)

// extractStrongMarkers pulls clearly distinctive substrings out of extracted
// data: JWTs, long hex hashes, quoted SQL-dump values, and credential-looking
// lines. These are unlikely to appear by chance, so finding one in a replayed
// response confirms the original proof still reproduces.
func extractStrongMarkers(data string) []string {
	var markers []string
	seen := map[string]bool{}

	add := func(value string) {
		value = strings.TrimSpace(value)
		if len(value) < 6 || seen[value] {
			return
		}

		seen[value] = true
		markers = append(markers, value)
	}

	for _, m := range jwtMarkerRe.FindAllString(data, -1) {
		add(m)
	}

	for _, m := range hexHashRe.FindAllString(data, -1) {
		add(m)
	}

	for _, m := range quotedRe.FindAllString(data, -1) {
		add(strings.Trim(m, "'"))
	}

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if credLineRe.MatchString(line) {
			add(line)
		}
	}

	return markers
}

// bodyHashTrimmed hashes a body after collapsing whitespace, so trivial
// formatting differences do not break an otherwise identical match.
func bodyHashTrimmed(body string) string {
	normalized := strings.Join(strings.Fields(body), " ")
	sum := sha256.Sum256([]byte(normalized))

	return hex.EncodeToString(sum[:])
}
