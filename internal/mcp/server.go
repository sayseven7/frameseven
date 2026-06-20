// Package mcp exposes the FrameSeven MCP server.
package mcp

import (
	"context"
	"log"
	"net/http"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "frameseven-mcp"
	serverVersion = "development"
	serverTitle   = "FrameSeven MCP Server"
	serverDocs    = "https://github.com/sayseven7/frameseven"
)

const serverInstructions = `Exposes FrameSeven v1 scanner tools:

Tools:
  recon, sqli, access, ssrf, lfi, misconfig, ratelimit, cve,
  crawler, content, subdomain, ports, nmap, sqlmap, bannergrab

Engagement workflow (manual findings, triage, consolidated report):
  - engagement_open opens a persistent store for a target.
  - finding_add injects manual findings, including extracted_data (dumps,
    cracked credentials, exfiltrated files) that the scanner cannot produce.
  - finding_update attaches data or overrides severity on a stored finding.
  - triage flags false positives (auto SPA index.html heuristic plus overrides).
  - report_engagement renders the consolidated, triaged report from the store.
  - recon, sqli, report, and the other scan tools accept an optional
    engagement_id to append their findings to a store automatically.

Tips:
  - normalize_tools validates a selection without running any probes.
  - extra_tools composes multiple scanners in a single call.
  - timeout_seconds and rate_requests override scan defaults.
  - report runs the selected tools and returns the result in the CLI report
    format (text and/or Markdown) for a CLI-identical write-up.

Resources:
  - Pentest playbooks from yaklang/hack-skills are exposed as MCP resources
    under skill://hack-skills/v1/. Read them for attack methodology and payload
    references (for example skill://hack-skills/v1/sqli-sql-injection/SKILL.md).

Before running any test, analysis, or exploitation, always load and apply
the relevant skill from the skills directory. Use the available resources
to guide your approach (for example skill://hack-skills/v1/xss-cross-site-scripting/SKILL.md
before testing XSS, skill://hack-skills/v1/sqli-sql-injection/SKILL.md before
testing SQL injection, and so on).`

// NewServer builds the FrameSeven MCP server.
func NewServer() *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    serverName,
		Version: serverVersion,
		Title:   serverTitle,
	}, &mcpsdk.ServerOptions{
		Instructions: serverInstructions,
		Capabilities: &mcpsdk.ServerCapabilities{
			Tools: &mcpsdk.ToolCapabilities{
				ListChanged: false,
			},
			Resources: &mcpsdk.ResourceCapabilities{
				ListChanged: false,
			},
			Logging: &mcpsdk.LoggingCapabilities{},
		},
		KeepAlive: 30 * time.Second,
	})

	server.AddReceivingMiddleware(createLoggingMiddleware())

	RegisterTools(server)
	RegisterResources(server)

	return server
}

// Run starts the MCP server over stdin/stdout.
func Run(ctx context.Context) error {
	log.Printf("MCP server starting on stdio transport")
	return NewServer().Run(ctx, &mcpsdk.StdioTransport{})
}

// NewStreamableHTTPHandler builds the HTTP handler used by remote MCP clients.
func NewStreamableHTTPHandler() http.Handler {
	server := NewServer()

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return server
	}, nil))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	return mux
}

// RunHTTP starts the MCP server over Streamable HTTP.
func RunHTTP(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewStreamableHTTPHandler(),
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("MCP server listening on http://%s", addr)

	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}

	return err
}
