// Package ports performs light TCP checks against common web-facing ports.
package ports

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

var commonPorts = []int{80, 443, 8000, 8080, 8443, 3000}

// probeWorkers caps how many TCP connect attempts run at once. The probes are
// independent, but the limit stays conservative so the tool does not raise the
// default scan load.
const probeWorkers = 6

// Run checks the target port and common web ports with TCP connect attempts.
func Run(cfg *config.Config, _ *http.Client, _ *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	host := base.Hostname()
	if host == "" {
		return nil
	}

	timeout := cfg.Timeout
	if timeout <= 0 || timeout > 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}

	candidates := portsFor(base)
	openFlags := make([]bool, len(candidates))

	workers := probeWorkers
	if workers > len(candidates) {
		workers = len(candidates)
	}

	jobs := make(chan int)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for index := range jobs {
				addr := net.JoinHostPort(host, strconv.Itoa(candidates[index]))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					continue
				}

				_ = conn.Close()
				openFlags[index] = true
			}
		}()
	}

	for index := range candidates {
		jobs <- index
	}
	close(jobs)
	wg.Wait()

	// Rebuild the open list in candidate order so output stays deterministic.
	var open []string
	for index, isOpen := range openFlags {
		if isOpen {
			open = append(open, strconv.Itoa(candidates[index]))
		}
	}

	if len(open) == 0 {
		return nil
	}

	return []finding.Finding{{
		Title:       "Open web-facing TCP ports found",
		Module:      "ports",
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "One or more common web-facing TCP ports accepted connections.",
		Evidence: finding.Evidence{
			Extracted: "open ports: " + strings.Join(open, ", "),
		},
		NextSteps: []string{
			"Confirm each open service is in scope and intentionally exposed.",
			"Use a dedicated service scanner for deeper enumeration when authorized.",
		},
	}}
}

func portsFor(base *url.URL) []int {
	seen := map[int]bool{}
	var ports []int

	add := func(port int) {
		if port <= 0 || seen[port] {
			return
		}

		seen[port] = true
		ports = append(ports, port)
	}

	if base.Port() != "" {
		if port, err := strconv.Atoi(base.Port()); err == nil {
			add(port)
		}
	} else if base.Scheme == "https" {
		add(443)
	} else {
		add(80)
	}

	for _, port := range commonPorts {
		add(port)
	}

	return ports
}
