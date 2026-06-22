package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/scanner"
)

func runWizard(input io.Reader, output io.Writer, opts options) (options, bool) {
	reader := bufio.NewReader(input)

	writeBanner(output)
	fmt.Fprintln(output, "Interactive scan setup")
	fmt.Fprintln(output)

	opts.target = prompt(reader, output, "Target URL", opts.target)
	opts.timeout = promptDuration(reader, output, "Per-request timeout", opts.timeout)
	opts.toolTimeout = promptDuration(reader, output, "Per-tool timeout", opts.toolTimeout)
	opts.concurrency = promptInt(reader, output, "Tool concurrency", opts.concurrency)
	opts.rate = promptInt(reader, output, "Rate-limit request count", opts.rate)
	opts.userAgent = promptUserAgent(reader, output, opts.userAgent)
	opts.outputDir = prompt(reader, output, "Output directory", opts.outputDir)
	opts.tools = promptTools(reader, output, opts.tools)

	authAnswer := prompt(reader, output, "Use browser-based authentication? [y/N]", "")
	if strings.EqualFold(authAnswer, "y") || strings.EqualFold(authAnswer, "yes") {
		opts.authBrowser = true
	}

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Active scan sends destructive, state-changing probes (PUT/DELETE methods,")
	fmt.Fprintln(output, "IDOR identifier mutation) that can modify or expose data on the target.")
	activeAnswer := prompt(reader, output, "Enable destructive active probes? [y/N]", "")
	opts.activeScan = strings.EqualFold(activeAnswer, "y") || strings.EqualFold(activeAnswer, "yes")

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Scan configuration")
	fmt.Fprintf(output, "  Target:     %s\n", opts.target)
	fmt.Fprintf(output, "  Timeout:    %s\n", opts.timeout)
	fmt.Fprintf(output, "  Tool limit: %s\n", opts.toolTimeout)
	fmt.Fprintf(output, "  Concurrency: %d\n", opts.concurrency)
	fmt.Fprintf(output, "  Rate count: %d\n", opts.rate)
	fmt.Fprintf(output, "  User-Agent: %s\n", opts.userAgent)
	fmt.Fprintf(output, "  Output:     %s\n", opts.outputDir)
	fmt.Fprintf(output, "  Tools:    %s\n", strings.Join(opts.tools, ", "))
	fmt.Fprintf(output, "  Active scan: %t\n", opts.activeScan)

	if opts.yes {
		return opts, true
	}

	fmt.Fprintln(output)
	fmt.Fprintln(output, "This scan sends active security probes and may affect target state.")

	answer := prompt(reader, output, "Continue? [y/N]", "")

	return opts, strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

func prompt(reader *bufio.Reader, output io.Writer, label, defaultValue string) string {
	if defaultValue == "" {
		fmt.Fprintf(output, "%s: ", label)
	} else {
		fmt.Fprintf(output, "%s [%s]: ", label, defaultValue)
	}

	value, err := reader.ReadString('\n')
	if err != nil && len(value) == 0 {
		return defaultValue
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}

	return value
}

func promptDuration(reader *bufio.Reader, output io.Writer, label string, defaultValue time.Duration) time.Duration {
	for {
		value := prompt(reader, output, label, defaultValue.String())
		duration, err := time.ParseDuration(value)
		if err == nil && duration > 0 {
			return duration
		}

		fmt.Fprintln(output, "Enter a positive duration such as 10s or 1m.")
	}
}

func promptInt(reader *bufio.Reader, output io.Writer, label string, defaultValue int) int {
	for {
		value := prompt(reader, output, label, strconv.Itoa(defaultValue))
		number, err := strconv.Atoi(value)
		if err == nil && number > 0 {
			return number
		}

		fmt.Fprintln(output, "Enter a positive whole number.")
	}
}

func promptUserAgent(reader *bufio.Reader, output io.Writer, current string) string {
	fmt.Fprintln(output)
	fmt.Fprintln(output, "User-Agent options")
	fmt.Fprintf(output, "  %d) %s\n", 0, "random  - pick a realistic browser agent (default)")
	for i, ua := range config.UserAgents {
		fmt.Fprintf(output, "  %d) %s\n", i+1, ua)
	}

	defaultValue := "random"
	if strings.TrimSpace(current) != "" {
		defaultValue = current
	}

	for {
		value := strings.TrimSpace(prompt(reader, output, "User-Agent (number, custom string, or random)", defaultValue))

		if value == "" || strings.EqualFold(value, "random") {
			return config.RandomUserAgent()
		}

		number, err := strconv.Atoi(value)
		if err != nil {
			// Anything that is not a number is treated as a custom agent.
			return value
		}

		if number == 0 {
			return config.RandomUserAgent()
		}

		if number >= 1 && number <= len(config.UserAgents) {
			return config.UserAgents[number-1]
		}

		fmt.Fprintf(output, "Choose a number between 0 and %d, or type a custom User-Agent.\n", len(config.UserAgents))
	}
}

func promptTools(reader *bufio.Reader, output io.Writer, current []string) []string {
	defaultValue := "default"
	if len(current) > 0 {
		defaultValue = strings.Join(current, ",")
	}

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Available tools")
	for i, tool := range scanner.Tools {
		fmt.Fprintf(output, "  %d) %-10s %s\n", i+1, tool.Name, tool.Description)
	}
	fmt.Fprintf(output, "  %-3s %-10s %s\n", "all", "", "Run every available tool")

	for {
		value := prompt(reader, output, "Tools to run (numbers or names, comma-separated)", defaultValue)
		selected, err := parseToolList(value)
		if err == nil {
			return selected
		}

		fmt.Fprintf(output, "%v\n", err)
	}
}
