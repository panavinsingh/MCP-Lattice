// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
	"github.com/panavinsingh/MCP-Lattice/internal/discovery"
	"github.com/panavinsingh/MCP-Lattice/internal/reporter"
	"github.com/panavinsingh/MCP-Lattice/internal/scanner"
	"github.com/panavinsingh/MCP-Lattice/internal/templates"
)

var (
	version = "0.1.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mcp-lattice",
		Short: "MCP-Lattice — Security scanner for Model Context Protocol servers",
		Long: `MCP-Lattice is the first comprehensive security scanner for the MCP ecosystem.
It auto-discovers MCP configurations, connects to every configured server,
and runs 30+ detection templates across a three-layer detection engine.

Finds tool poisoning, prompt injection, SSRF, auth bypasses, credential exposure,
and dangerous tool combinations that no individual tool scan would catch.`,
	}

	// Global flags
	var scanCfg config.ScanConfig
	rootCmd.PersistentFlags().BoolVar(&scanCfg.NoColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().BoolVarP(&scanCfg.Verbose, "verbose", "v", false, "Verbose output")

	// Scan command
	scanCmd := buildScanCommand(&scanCfg)
	rootCmd.AddCommand(scanCmd)

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("MCP-Lattice v%s\nCommit: %s\nBuilt: %s\n", version, commit, date)
		},
	}
	rootCmd.AddCommand(versionCmd)

	// Template commands
	templateCmd := buildTemplateCommand()
	rootCmd.AddCommand(templateCmd)

	// Report command
	reportCmd := buildReportCommand(&scanCfg)
	rootCmd.AddCommand(reportCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildScanCommand(scanCfg *config.ScanConfig) *cobra.Command {
	var configPath string
	var templateDirs []string
	var severityThreshold string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan MCP servers for security vulnerabilities",
		Long: `Auto-discovers MCP configurations across Claude Desktop, Cursor, Windsurf,
VS Code, and Gemini CLI, connects to every server, and runs all detection templates.

Run with no arguments for zero-config scanning:
  mcp-lattice scan

Or specify a config file:
  mcp-lattice scan --config ~/.cursor/mcp.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(scanCfg, configPath, templateDirs, severityThreshold)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to MCP config file (auto-discovers if not set)")
	cmd.Flags().StringSliceVarP(&templateDirs, "template-dir", "t", nil, "Additional template directories")
	cmd.Flags().StringVarP(&scanCfg.OutputFormat, "format", "f", "table", "Output format: table, json, sarif, html")
	cmd.Flags().StringVarP(&scanCfg.OutputFile, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&severityThreshold, "severity-threshold", "info", "Minimum severity: info, low, medium, high, critical")
	cmd.Flags().IntVar(&scanCfg.Concurrency, "concurrency", 10, "Max concurrent server connections")
	cmd.Flags().IntVar(&scanCfg.Timeout, "timeout", 30, "Connection timeout in seconds")
	cmd.Flags().BoolVar(&scanCfg.EnableL2, "enable-l2", true, "Enable L2 semantic detection")
	cmd.Flags().BoolVar(&scanCfg.EnableL3, "enable-l3", true, "Enable L3 capability graph analysis")
	cmd.Flags().Float64Var(&scanCfg.SemanticThreshold, "semantic-threshold", 0.72, "L2 semantic similarity threshold")

	return cmd
}

func buildTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage detection templates",
	}

	// template list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all available templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs := scanner.FindTemplateDirs()
			if len(dirs) == 0 {
				fmt.Println("No template directories found.")
				return nil
			}

			loader := templates.NewLoader(dirs)
			tmpls, err := loader.LoadAll()
			if err != nil {
				return fmt.Errorf("loading templates: %w", err)
			}

			fmt.Printf("Found %d templates in %d directories:\n\n", len(tmpls), len(dirs))
			for _, t := range tmpls {
				sevColor := getSeverityPrintColor(t.Info.Severity)
				sevColor.Printf("  [%s] ", strings.ToUpper(t.Info.Severity))
				fmt.Printf("%s (%s)\n", t.Info.Name, t.ID)
			}
			return nil
		},
	}

	// template validate
	validateCmd := &cobra.Command{
		Use:   "validate [dir]",
		Short: "Validate templates in a directory",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "templates"
			if len(args) > 0 {
				dir = args[0]
			}

			errs := templates.ValidateTemplateDir(dir)
			if len(errs) == 0 {
				color.New(color.FgGreen).Println("All templates valid.")
				return nil
			}

			fmt.Printf("Found %d validation errors:\n", len(errs))
			for _, err := range errs {
				color.New(color.FgRed).Printf("  - %s\n", err)
			}
			return fmt.Errorf("%d templates failed validation", len(errs))
		},
	}

	cmd.AddCommand(listCmd, validateCmd)
	return cmd
}

func buildReportCommand(scanCfg *config.ScanConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate reports from previous scan results",
	}

	return cmd
}

func runScan(scanCfg *config.ScanConfig, configPath string, templateDirs []string, severityThreshold string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Parse severity threshold
	if severityThreshold != "" {
		sev, err := config.ParseSeverity(severityThreshold)
		if err != nil {
			return fmt.Errorf("invalid severity threshold: %w", err)
		}
		scanCfg.SeverityThreshold = sev
	}

	// Initialize defaults
	if scanCfg.Concurrency == 0 {
		scanCfg.Concurrency = 10
	}
	if scanCfg.Timeout == 0 {
		scanCfg.Timeout = 30
	}

	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Println("\n  MCP-Lattice v" + version + " — MCP Security Scanner")
	fmt.Println("  " + strings.Repeat("─", 45))

	// Step 1: Discover MCP configurations
	fmt.Println("\n  [1/4] Discovering MCP configurations...")

	var servers []config.MCPServerConfig
	disc := discovery.New()

	if configPath != "" {
		s, err := disc.DiscoverFromPath(configPath)
		if err != nil {
			return fmt.Errorf("parsing config: %w", err)
		}
		servers = s
	} else {
		s, err := disc.Discover()
		if err != nil {
			color.New(color.FgYellow).Printf("  Warning: %v\n", err)
			color.New(color.FgYellow).Println("  No MCP configs found. Use --config to specify a config file.")
			return nil
		}
		servers = s
	}

	fmt.Printf("  Found %d MCP server(s)\n", len(servers))
	for _, s := range servers {
		fmt.Printf("    - %s (%s via %s)\n", s.Name, s.Source, s.Transport)
	}

	// Step 2: Load templates
	fmt.Println("\n  [2/4] Loading detection templates...")

	allTemplateDirs := scanner.FindTemplateDirs()
	allTemplateDirs = append(allTemplateDirs, templateDirs...)

	if len(allTemplateDirs) == 0 {
		color.New(color.FgYellow).Println("  Warning: No template directories found.")
		color.New(color.FgYellow).Println("  Templates should be in ./templates/ or ~/.mcp-lattice/templates/")
		return nil
	}

	loader := templates.NewLoader(allTemplateDirs)
	tmpls, err := loader.LoadAll()
	if err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}

	fmt.Printf("  Loaded %d templates from %d directories\n", len(tmpls), len(allTemplateDirs))

	// Step 3: Run scan
	fmt.Println("\n  [3/4] Scanning MCP servers...")

	engine := scanner.NewEngine(scanCfg, tmpls)
	engine.OnProgress = func(server, status string) {
		if scanCfg.Verbose {
			if server != "" {
				fmt.Printf("    [%s] %s\n", server, status)
			} else {
				fmt.Printf("    %s\n", status)
			}
		}
	}

	result, err := engine.Scan(ctx, servers)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Step 4: Report
	fmt.Println("\n  [4/4] Generating report...")

	var w *os.File
	if scanCfg.OutputFile != "" {
		w, err = os.Create(scanCfg.OutputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	switch scanCfg.OutputFormat {
	case "json":
		r := reporter.NewJSONReporter()
		return r.Report(w, result)
	case "sarif":
		r := reporter.NewSARIFReporter()
		return r.Report(w, result)
	case "html":
		r := reporter.NewHTMLReporter(result.Servers)
		return r.Report(w, result)
	default:
		r := reporter.NewTableReporter(scanCfg.NoColor)
		return r.Report(w, result)
	}
}

func getSeverityPrintColor(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return color.New(color.FgRed, color.Bold)
	case "high":
		return color.New(color.FgYellow, color.Bold)
	case "medium":
		return color.New(color.FgMagenta)
	case "low":
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}
