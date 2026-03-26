# Contributing to MCP-Lattice

Thank you for your interest in contributing to MCP-Lattice. This document covers everything you need to get started, from the easiest contributions (detection templates) to Go code changes.

---

## Table of Contents

1. [Ways to Contribute](#ways-to-contribute)
2. [Contributing Templates](#contributing-templates)
3. [Contributing Go Code](#contributing-go-code)
4. [Development Setup](#development-setup)
5. [Code Style](#code-style)
6. [Pull Request Process](#pull-request-process)
7. [Issue Templates](#issue-templates)
8. [Code of Conduct](#code-of-conduct)

---

## Ways to Contribute

| Contribution Type | Difficulty | Impact |
|---|---|---|
| Report a bug | Easy | High |
| Submit a new detection template | Easy | High |
| Improve documentation | Easy | Medium |
| Add test cases | Medium | High |
| Fix a bug | Medium | High |
| Add a new detection engine feature | Hard | High |
| Add a new output format | Medium | Medium |
| Add a new config discovery target | Medium | Medium |

---

## Contributing Templates

Detection templates are the easiest and highest-impact way to contribute. You do not need to write any Go code.

### Quick Steps

1. Read the [Template Authoring Guide](TEMPLATE_AUTHORING.md) to understand the YAML schema.
2. Create a new `.yaml` file in the appropriate `templates/<category>/` directory.
3. Give it a unique `id` following the `<category>/<name>` convention.
4. Add at least one analysis block (pattern, semantic, or capability_graph).
5. Add a classification block with `attack-class`, `cosai-category`, and `owasp-agentic`.
6. Validate your template: `mcp-lattice template validate <path-to-template.yaml>`
7. Test it against known-good and known-bad inputs to verify precision.
8. Submit a pull request.

### Template Checklist

Before submitting a template PR, verify:

- [ ] Template has a unique `id` that does not conflict with existing templates.
- [ ] `schema_version` is set to `"1"`.
- [ ] `info.severity` is appropriate (do not inflate severity).
- [ ] `info.description` clearly explains what the template detects and why it matters.
- [ ] `info.author` is set to your GitHub handle.
- [ ] At least one reference URL is provided in `info.references`.
- [ ] Regex patterns are specific enough to avoid false positives on benign tools.
- [ ] If using semantic analysis, threshold is between 0.75 and 0.90.
- [ ] If using semantic analysis, malicious intents are specific and descriptive.
- [ ] Classification fields are filled in correctly.
- [ ] Template passes `mcp-lattice template validate`.
- [ ] Template produces zero findings against the benign test corpus (`make test-templates`).

### Where to Put Templates

| Category | Directory | Examples |
|---|---|---|
| Tool poisoning | `templates/tool-poisoning/` | Hidden instructions, rug pulls, shadowing |
| Prompt injection | `templates/prompt-injection/` | Direct injection, Unicode obfuscation, Base64 |
| Code execution | `templates/code-execution/` | Command injection, path traversal, sandbox escape |
| Authentication | `templates/auth/` | Zero-auth servers, credential theft, OAuth issues |
| Data exfiltration | `templates/data-exfiltration/` | Parameter exfiltration, DNS exfiltration, image URLs |
| Supply chain | `templates/supply-chain/` | Typosquatting, dependency confusion |
| Capability graph | `templates/capability-graph/` | Toxic tool combinations |

---

## Contributing Go Code

### Before You Start

1. Check existing issues to see if someone is already working on the same thing.
2. For non-trivial changes, open an issue first to discuss the approach.
3. For new features, describe the use case and proposed design in the issue.

### Code Organization

| Directory | Purpose |
|---|---|
| `cmd/mcp-lattice/` | CLI entry point and subcommands |
| `internal/discovery/` | MCP config file discovery |
| `internal/connector/` | MCP server connections (stdio, SSE, HTTP) |
| `internal/scanner/` | Scan orchestration |
| `internal/detection/` | Detection engines (pattern, semantic, graph) |
| `internal/graph/` | Capability graph data structures and algorithms |
| `internal/templates/` | Template loading and validation |
| `internal/reporter/` | Output formatters (table, JSON, SARIF, HTML) |
| `templates/` | YAML detection templates |

### Key Interfaces

If you are adding a new detection layer or output format, implement the relevant interface:

```go
// Detector runs analysis on a tool and returns findings.
type Detector interface {
    Name() string
    Analyze(ctx context.Context, tool *mcp.Tool, template *Template) ([]RawFinding, error)
}

// Reporter formats findings for output.
type Reporter interface {
    Format() string
    Write(w io.Writer, findings []Finding) error
}

// Discoverer locates MCP configuration files.
type Discoverer interface {
    Name() string
    Discover() ([]ServerConfig, error)
}
```

---

## Development Setup

### Prerequisites

- **Go 1.22 or later** ([download](https://go.dev/dl/))
- **Git**
- **Make** (optional but recommended; on Windows, use Git Bash or WSL)

### Clone and Build

```bash
git clone https://github.com/panavinsingh/MCP-Lattice.git
cd mcp-lattice
make build
```

This produces a `mcp-lattice` binary (or `mcp-lattice.exe` on Windows) in the `bin/` directory.

### Run Tests

```bash
make test
```

This runs all Go unit tests and template validation tests.

### Run Linters

```bash
make lint
```

This runs `gofmt`, `go vet`, and `staticcheck`.

### Full CI Check

```bash
make ci
```

This runs the full CI pipeline locally: `lint` + `test` + `build`.

### Makefile Reference

| Target | Description |
|---|---|
| `make build` | Build the `mcp-lattice` binary |
| `make test` | Run all tests |
| `make test-templates` | Validate all templates and run them against the test corpus |
| `make lint` | Run `gofmt -l`, `go vet`, and `staticcheck` |
| `make ci` | Run the full CI pipeline (`lint`, `test`, `build`) |
| `make clean` | Remove build artifacts |
| `make install` | Install `mcp-lattice` to `$GOPATH/bin` |

---

## Code Style

MCP-Lattice follows standard Go conventions:

- **Formatting**: All code must be formatted with `gofmt`. Run `gofmt -w .` before committing.
- **Vetting**: Code must pass `go vet ./...` with no warnings.
- **Naming**: Follow [Go naming conventions](https://go.dev/doc/effective_go#names). Exported names use PascalCase; unexported names use camelCase.
- **Errors**: Return errors rather than panicking. Wrap errors with context using `fmt.Errorf("operation: %w", err)`.
- **Comments**: All exported types, functions, and methods must have a doc comment. Comments should be complete sentences starting with the name of the thing being described.
- **Tests**: New code must include tests. Aim for at least 80% coverage on new files. Use table-driven tests where appropriate.
- **Dependencies**: Minimize external dependencies. Prefer standard library solutions. New dependencies require discussion in the PR.

### Import Ordering

Group imports in this order, separated by blank lines:

```go
import (
    // Standard library
    "context"
    "fmt"

    // Third-party packages
    "github.com/spf13/cobra"

    // Internal packages
    "github.com/panavinsingh/MCP-Lattice/internal/detection"
)
```

---

## Pull Request Process

### Step-by-Step

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-change main
   ```

2. **Make your changes** following the code style guidelines above.

3. **Add or update tests** for your changes.

4. **Run the full CI check** locally:
   ```bash
   make ci
   ```

5. **Commit** with a clear, descriptive commit message:
   ```
   detection: add Base64 payload scanning to pattern engine

   The pattern engine now decodes Base64-encoded strings found in tool
   descriptions and applies regex patterns to the decoded content. This
   detects attackers who encode malicious instructions to evade pattern
   matching.

   Closes #42
   ```

6. **Push** your branch and open a pull request against `main`.

7. **Fill in the PR template** with:
   - A description of what changed and why.
   - How to test the change.
   - Any breaking changes or migration steps.

### PR Requirements

All pull requests must:

- [ ] Pass CI (lint, test, build).
- [ ] Include tests for new functionality.
- [ ] Not decrease overall test coverage.
- [ ] Have a clear commit history (squash fixup commits before merging).
- [ ] Be reviewed by at least one maintainer.

### Review Timeline

We aim to review all PRs within 5 business days. If your PR has not received a review after that time, feel free to ping in the PR comments.

---

## Issue Templates

We provide three issue templates to help you report bugs, request features, and submit new detection templates:

| Template | When to Use |
|---|---|
| [Bug Report](../.github/ISSUE_TEMPLATE/bug_report.md) | You found a bug in MCP-Lattice's behavior |
| [Feature Request](../.github/ISSUE_TEMPLATE/feature_request.md) | You have an idea for a new feature or improvement |
| [New Template](../.github/ISSUE_TEMPLATE/new_template.md) | You want to propose a new detection template |

When filing an issue, please use the appropriate template and fill in all required sections.

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to a positive environment:

- Using welcoming and inclusive language.
- Being respectful of differing viewpoints and experiences.
- Gracefully accepting constructive criticism.
- Focusing on what is best for the community.
- Showing empathy towards other community members.

Examples of unacceptable behavior:

- The use of sexualized language or imagery and unwelcome sexual attention or advances.
- Trolling, insulting or derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information without explicit permission.
- Other conduct which could reasonably be considered inappropriate in a professional setting.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project maintainers at security@mcp-lattice.dev. All complaints will be reviewed and investigated and will result in a response that is deemed necessary and appropriate to the circumstances.

Project maintainers who do not follow or enforce the Code of Conduct in good faith may face temporary or permanent repercussions as determined by other members of the project's leadership.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org/), version 2.1.
