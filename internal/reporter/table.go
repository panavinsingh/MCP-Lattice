// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// TableReporter outputs findings as a color-coded terminal table.
type TableReporter struct {
	noColor bool
}

// NewTableReporter creates a new table reporter.
func NewTableReporter(noColor bool) *TableReporter {
	if noColor {
		color.NoColor = true
	}
	return &TableReporter{noColor: noColor}
}

// Report writes the scan result as a terminal table.
func (r *TableReporter) Report(w io.Writer, result *config.ScanResult) error {
	// Header
	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Fprintf(w, "\n  MCP-Lattice v0.1.0 — MCP Security Scanner\n")
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("─", 50))

	// Summary
	counts := countBySeverity(result.Findings)
	fmt.Fprintf(w, "  Servers scanned: %d | Tools scanned: %d | Findings: %d\n",
		result.ServersFound, result.ToolsScanned, len(result.Findings))

	critColor := color.New(color.FgRed, color.Bold)
	highColor := color.New(color.FgYellow, color.Bold)
	medColor := color.New(color.FgMagenta)
	lowColor := color.New(color.FgBlue)

	fmt.Fprintf(w, "  ")
	critColor.Fprintf(w, "Critical: %d", counts["critical"])
	fmt.Fprintf(w, " | ")
	highColor.Fprintf(w, "High: %d", counts["high"])
	fmt.Fprintf(w, " | ")
	medColor.Fprintf(w, "Medium: %d", counts["medium"])
	fmt.Fprintf(w, " | ")
	lowColor.Fprintf(w, "Low: %d", counts["low"])
	fmt.Fprintf(w, " | Info: %d\n", counts["info"])

	fmt.Fprintf(w, "\n  %s\n\n", strings.Repeat("─", 50))

	if len(result.Findings) == 0 {
		successColor := color.New(color.FgGreen, color.Bold)
		successColor.Fprintf(w, "  No security issues found.\n\n")
		return nil
	}

	// Group findings by severity
	grouped := groupBySeverity(result.Findings)

	for _, sev := range []config.Severity{
		config.SeverityCritical, config.SeverityHigh,
		config.SeverityMedium, config.SeverityLow, config.SeverityInfo,
	} {
		findings, ok := grouped[sev]
		if !ok || len(findings) == 0 {
			continue
		}

		sevColor := getSeverityColor(sev)
		sevColor.Fprintf(w, "  [%s]\n", strings.ToUpper(sev.String()))

		for _, f := range findings {
			fmt.Fprintf(w, "  ├─ ")
			sevColor.Fprintf(w, "%s", f.Title)
			fmt.Fprintf(w, "\n")

			dimColor := color.New(color.Faint)
			fmt.Fprintf(w, "  │  Server: %s", f.ServerName)
			if f.ToolName != "" {
				fmt.Fprintf(w, " | Tool: %s", f.ToolName)
			}
			fmt.Fprintf(w, " | Layer: L%d", f.Layer)
			fmt.Fprintf(w, " | Confidence: %.0f%%\n", f.Confidence*100)

			if f.Evidence != "" {
				evidence := f.Evidence
				if len(evidence) > 120 {
					evidence = evidence[:120] + "..."
				}
				dimColor.Fprintf(w, "  │  Evidence: %s\n", evidence)
			}

			if f.Classification.CVE != "" {
				fmt.Fprintf(w, "  │  CVE: %s\n", f.Classification.CVE)
			}

			if f.Remediation != "" {
				remediation := strings.TrimSpace(f.Remediation)
				if len(remediation) > 150 {
					remediation = remediation[:150] + "..."
				}
				fmt.Fprintf(w, "  │  Fix: %s\n", remediation)
			}

			fmt.Fprintf(w, "  │\n")
		}

		fmt.Fprintf(w, "\n")
	}

	// Server summary
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 50))
	fmt.Fprintf(w, "  Servers:\n")
	for name, sr := range result.Servers {
		if sr.Connected {
			fmt.Fprintf(w, "  ├─ %s: %d tools, %d resources\n", name, len(sr.Tools), len(sr.Resources))
		} else {
			dimColor := color.New(color.Faint)
			dimColor.Fprintf(w, "  ├─ %s: connection failed (%s)\n", name, sr.Error)
		}
	}
	fmt.Fprintf(w, "\n")

	return nil
}

func groupBySeverity(findings []config.Finding) map[config.Severity][]config.Finding {
	grouped := make(map[config.Severity][]config.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}

func getSeverityColor(s config.Severity) *color.Color {
	switch s {
	case config.SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case config.SeverityHigh:
		return color.New(color.FgYellow, color.Bold)
	case config.SeverityMedium:
		return color.New(color.FgMagenta)
	case config.SeverityLow:
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}
