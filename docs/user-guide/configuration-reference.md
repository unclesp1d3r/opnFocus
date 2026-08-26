# Configuration Reference

Complete reference for all opnDossier configuration options. Configuration can be set via command-line flags, environment variables, or configuration file with clear precedence order.

For how configuration precedence works and worked setup recipes, see [Configuring opnDossier](configuration.md).

## Global Options

These options are persistent flags available on all subcommands.

### Logging & Output

| Setting         | CLI Flag        | Environment Variable     | Config File   | Type    | Default  | Description                                |
| --------------- | --------------- | ------------------------ | ------------- | ------- | -------- | ------------------------------------------ |
| Verbose logging | `--verbose`     | `OPNDOSSIER_VERBOSE`     | `verbose`     | boolean | `false`  | Enable debug-level logging                 |
| Quiet mode      | `--quiet`       | `OPNDOSSIER_QUIET`       | `quiet`       | boolean | `false`  | Suppress all output except errors          |
| Color output    | `--color`       | `OPNDOSSIER_COLOR`       | -             | string  | `"auto"` | Color output: auto, always, never          |
| No progress     | `--no-progress` | `OPNDOSSIER_NO_PROGRESS` | `no_progress` | boolean | `false`  | Disable progress indicators                |
| Timestamps      | `--timestamps`  | -                        | -             | boolean | `false`  | Include timestamps in log output           |
| Minimal mode    | `--minimal`     | `OPNDOSSIER_MINIMAL`     | `minimal`     | boolean | `false`  | Minimal output (suppress progress/verbose) |
| Device type     | `--device-type` | -                        | -             | string  | `""`     | Force device type (auto-detected if empty) |
| Config file     | `--config`      | -                        | -             | string  | `""`     | Custom config file path                    |

## Convert Command Options

### Output Control

| Setting     | CLI Flag       | Environment Variable     | Config File   | Type    | Default      | Description                             |
| ----------- | -------------- | ------------------------ | ------------- | ------- | ------------ | --------------------------------------- |
| Output file | `-o, --output` | `OPNDOSSIER_OUTPUT_FILE` | `output_file` | string  | stdout       | Output file path                        |
| Format      | `-f, --format` | `OPNDOSSIER_FORMAT`      | `format`      | string  | `"markdown"` | Output format (see below)               |
| Force       | `--force`      | -                        | -             | boolean | `false`      | Overwrite existing files without prompt |

Supported formats: `markdown` (`md`), `json`, `yaml` (`yml`), `text` (`txt`), `html` (`htm`)

### Content & Formatting

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                                                                                     |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------- |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections: system, network, firewall, services, security                                                         |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)                                                                       |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping (alias for --wrap 0)                                                                      |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive detailed reports                                                                         |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables) |
| Redact           | `--redact`           | -                     | -           | boolean  | `false` | Redact sensitive fields (passwords, keys, etc.)                                                                 |

## Audit Command Options

The `audit` command is the dedicated entry point for security audit and compliance checks. See the [audit command documentation](commands/audit.md) for complete details.

### Audit-Specific Flags

| Setting            | CLI Flag          | Type     | Default  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------ | ----------------- | -------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Audit mode         | `--mode`          | string   | `"blue"` | Audit mode: `blue` (defensive audit with compliance), `red` (attack surface)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Compliance plugins | `--plugins`       | string[] | `[]`     | Comma-separated list: `stig`, `sans`, `firewall`. Only valid with `--mode blue`. Empty = all plugins run.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Plugin directory   | `--plugin-dir`    | string   | `""`     | Directory containing **third-party** dynamic `.so` compliance plugins. Does not affect the built-in `stig`/`sans`/`firewall` plugins (compiled into the binary; always available). **Linux/macOS/FreeBSD only — Go's `plugin` package is not implemented on Windows.** **Third-party plugins run with full process privileges; opnDossier does not verify signatures.** A preflight rejects symlinks, group/world-writable files and directories, and oversize (>64 MiB) files, and every load attempt is logged with a SHA-256 digest. See [audit -- Third-Party Plugin Security](commands/audit.md#third-party-plugin-security) for the full restriction list, threat scenarios, and operator responsibilities. Failed loads are non-fatal (warnings logged). |
| Failures only      | `--failures-only` | boolean  | `false`  | Show only failing controls in compliance tables. Only valid with `--mode blue` and markdown format.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

### Shared Output Flags

The `audit` command shares the following output and formatting flags with `convert`:

- `--format` / `-f` -- Output format (markdown, json, yaml, text, html)
- `--output` / `-o` -- Output file path (cannot be used with multiple input files)
- `--force` -- Overwrite existing files without prompt
- `--comprehensive` -- Generate detailed comprehensive reports
- `--redact` -- Redact sensitive fields (passwords, keys, etc.)
- `--wrap` -- Text wrap width
- `--no-wrap` -- Disable text wrapping
- `--include-tunables` -- Include all system tunables (markdown, text, HTML only)
- `--section` -- Filter output to specific sections

### Multi-File Audit Behavior

When auditing multiple files, the `--output` flag cannot be used. Each report is auto-named with an `-audit` suffix and format extension:

```bash
# Single file: --output allowed
opndossier audit config.xml --mode blue -o security-report.md

# Multiple files: auto-named outputs (config1-audit.md, config2-audit.md)
opndossier audit config1.xml config2.xml --mode blue
```

Path encoding for multi-file output:

- Bare filenames: `config.xml` → `config-audit.md`
- Paths with directories: `prod/site-a/config.xml` → `prod_site-a_config-audit.md`

### Usage Examples

```bash
# Blue team audit with all plugins (default when no --plugins specified)
opndossier audit config.xml --mode blue

# Blue team audit with specific plugins
opndossier audit config.xml --mode blue --plugins stig,sans

# Show only failing controls in blue mode
opndossier audit config.xml --mode blue --failures-only

# Red team attack surface analysis
opndossier audit config.xml --mode red

# Custom plugins directory
opndossier audit config.xml --mode blue --plugin-dir /opt/plugins

# Multi-file audit with JSON output
opndossier audit config1.xml config2.xml --mode blue --format json
```

## Display Command Options

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                                                                                     |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------- |
| Theme            | `--theme`            | `OPNDOSSIER_THEME`    | `theme`     | string   | `""`    | Rendering theme: auto, dark, light, none                                                                        |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections: system, network, firewall, services, security                                                         |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)                                                                       |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping                                                                                           |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive reports                                                                                  |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables) |
| Redact           | `--redact`           | -                     | -           | boolean  | `false` | Redact sensitive fields in output                                                                               |

## Validate Command Options

| Setting     | CLI Flag        | Environment Variable     | Config File   | Type    | Default | Description                             |
| ----------- | --------------- | ------------------------ | ------------- | ------- | ------- | --------------------------------------- |
| JSON output | `--json-output` | `OPNDOSSIER_JSON_OUTPUT` | `json_output` | boolean | `false` | Output validation errors in JSON format |

## Configuration File Format

### YAML Configuration File

Create `~/.opnDossier.yaml` with your preferred settings:

```yaml
# Logging Configuration
verbose: false
quiet: false

# Output Settings
format: markdown
wrap: 120
sections: []

# File Paths
input_file: ''
output_file: ''

# Display
theme: ''

# Advanced
no_progress: false
json_output: false
minimal: false
```

## Environment Variables

Every configuration key has an environment-variable equivalent. Uppercase the key, replace dots with underscores, and prefix it with `OPNDOSSIER_`:

- Flat keys — `verbose` → `OPNDOSSIER_VERBOSE`, `input_file` → `OPNDOSSIER_INPUT_FILE`
- Nested keys — `display.width` → `OPNDOSSIER_DISPLAY_WIDTH`, `logging.level` → `OPNDOSSIER_LOGGING_LEVEL`

### Complete variable reference

| Configuration Key              | Environment Variable                      | Type     | Default    |
| ------------------------------ | ----------------------------------------- | -------- | ---------- |
| `input_file`                   | `OPNDOSSIER_INPUT_FILE`                   | string   | ""         |
| `output_file`                  | `OPNDOSSIER_OUTPUT_FILE`                  | string   | ""         |
| `verbose`                      | `OPNDOSSIER_VERBOSE`                      | boolean  | false      |
| `debug`                        | `OPNDOSSIER_DEBUG`                        | boolean  | false      |
| `quiet`                        | `OPNDOSSIER_QUIET`                        | boolean  | false      |
| `format`                       | `OPNDOSSIER_FORMAT`                       | string   | "markdown" |
| `theme`                        | `OPNDOSSIER_THEME`                        | string   | ""         |
| `sections`                     | `OPNDOSSIER_SECTIONS`                     | []string | []         |
| `wrap`                         | `OPNDOSSIER_WRAP`                         | int      | -1         |
| `json_output`                  | `OPNDOSSIER_JSON_OUTPUT`                  | boolean  | false      |
| `minimal`                      | `OPNDOSSIER_MINIMAL`                      | boolean  | false      |
| `no_progress`                  | `OPNDOSSIER_NO_PROGRESS`                  | boolean  | false      |
| `display.width`                | `OPNDOSSIER_DISPLAY_WIDTH`                | int      | -1         |
| `display.pager`                | `OPNDOSSIER_DISPLAY_PAGER`                | boolean  | false      |
| `display.syntax_highlighting`  | `OPNDOSSIER_DISPLAY_SYNTAX_HIGHLIGHTING`  | boolean  | true       |
| `export.format`                | `OPNDOSSIER_EXPORT_FORMAT`                | string   | "markdown" |
| `export.directory`             | `OPNDOSSIER_EXPORT_DIRECTORY`             | string   | ""         |
| `export.backup`                | `OPNDOSSIER_EXPORT_BACKUP`                | boolean  | false      |
| `logging.level`                | `OPNDOSSIER_LOGGING_LEVEL`                | string   | "info"     |
| `logging.format`               | `OPNDOSSIER_LOGGING_FORMAT`               | string   | "text"     |
| `validation.strict`            | `OPNDOSSIER_VALIDATION_STRICT`            | boolean  | false      |
| `validation.schema_validation` | `OPNDOSSIER_VALIDATION_SCHEMA_VALIDATION` | boolean  | false      |

### Value encoding

Booleans accept `true`/`false` in any case, plus `1`/`0`. Lists are comma-separated.

```bash
export OPNDOSSIER_VERBOSE=1
export OPNDOSSIER_SECTIONS="system,network,firewall,dhcp"
export OPNDOSSIER_INPUT_FILE="/path/to/config.xml"
```

## Configuration Validation

opnDossier validates configuration values on startup. Invalid values will result in clear error messages:

```bash
# Invalid format
$ opndossier convert -f invalid config.xml
Error: invalid format "invalid", must be one of: markdown, md, json, yaml, yml, text, txt, html, htm

# Mutually exclusive flags
$ opndossier --verbose --quiet convert config.xml
Error: if any flags in the group [verbose quiet] are set none of the others can be

# Invalid color mode
$ opndossier --color invalid convert config.xml
Error: invalid color "invalid", must be one of: auto, always, never
```

## Related

- [Configuring opnDossier](configuration.md) -- precedence, recipes, and troubleshooting
- [Commands Overview](commands/overview.md) -- per-command flag reference
- [Audit Command](commands/audit.md) -- dedicated security audit and compliance checks
- [XML Field Reference](../xml-field-reference.md) -- OPNsense XML schema details
