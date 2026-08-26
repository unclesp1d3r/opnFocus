# Configuring opnDossier

opnDossier runs with no configuration at all. Everything on this page is optional — reach for it when you want persistent defaults, per-environment settings, or reproducible behaviour in automation.

This page explains *how* configuration resolves and gives worked recipes. For the exhaustive list of every key, flag, environment variable, type, and default, see the [Configuration Reference](configuration-reference.md).

## How settings resolve

opnDossier layers four sources. When the same setting appears in more than one, the higher-priority source wins:

| Priority    | Source                | Example                   |
| ----------- | --------------------- | ------------------------- |
| 1 (highest) | Command-line flags    | `--verbose`               |
| 2           | Environment variables | `OPNDOSSIER_VERBOSE=true` |
| 3           | Configuration file    | `~/.opnDossier.yaml`      |
| 4 (lowest)  | Built-in defaults     | —                         |

Each layer overrides only the keys it actually sets, so a config file and an environment variable can contribute different settings to the same run.

### Precedence in practice

Given this config file:

```yaml
# ~/.opnDossier.yaml
verbose: false
format: markdown
```

...and this invocation:

```bash
export OPNDOSSIER_FORMAT=json
opndossier --verbose convert config.xml
```

The effective settings are `verbose: true` (CLI flag beat the file) and `format: json` (environment variable beat the file). Run `opndossier --verbose config show` at any time to see the merged result and which file it came from.

## Using a configuration file

opnDossier looks for `~/.opnDossier.yaml` by default. Point it elsewhere with `--config`:

```bash
opndossier --config /path/to/custom-config.yaml convert config.xml
opndossier --config ./.opnDossier.yaml convert config.xml
```

Generate a fully annotated starter file rather than writing one by hand:

```bash
opndossier config init                          # writes ~/.opnDossier.yaml
opndossier config init --output ./project.yaml  # or somewhere else
```

Then check it before relying on it:

```bash
opndossier config validate
opndossier config show
```

## Using environment variables

Every configuration key has an environment variable equivalent: uppercase the key, replace dots with underscores, and prefix it with `OPNDOSSIER_`.

- `verbose` → `OPNDOSSIER_VERBOSE`
- `display.width` → `OPNDOSSIER_DISPLAY_WIDTH`
- `logging.level` → `OPNDOSSIER_LOGGING_LEVEL`

Booleans accept `true`/`false` in any case, plus `1`/`0`. Lists are comma-separated:

```bash
export OPNDOSSIER_VERBOSE=1
export OPNDOSSIER_SECTIONS="system,network,firewall,dhcp"
```

The [Configuration Reference](configuration-reference.md#environment-variables) has the complete key-to-variable table.

## Recipes

### Development and debugging

```yaml
# ~/.opnDossier.yaml
verbose: true
logging:
  level: debug
  format: text
validation:
  strict: true
display:
  syntax_highlighting: true
  width: 120
```

### CI/CD pipelines

Environment variables suit CI better than a checked-in file — they keep the config next to the job definition and out of the repository:

```bash
#!/usr/bin/env bash
export OPNDOSSIER_QUIET=true
export OPNDOSSIER_JSON_OUTPUT=true
export OPNDOSSIER_VALIDATION_STRICT=true
export OPNDOSSIER_NO_PROGRESS=true

opndossier validate config.xml
opndossier convert config.xml -o report.md
```

### Scheduled production reports

```yaml
# ~/.opnDossier.yaml
verbose: false
quiet: false
minimal: true
no_progress: true
format: markdown
export:
  format: markdown
  backup: true
  directory: /var/reports/opnsense
logging:
  level: warn
  format: json
validation:
  strict: true
```

### Airgapped and offline systems

opnDossier makes no network calls, so nothing here disables telemetry — this recipe simply pins the input and output paths so the tool can run unattended from removable media:

```yaml
# ~/.opnDossier.yaml
input_file: /mnt/configs/opnsense-config.xml
output_file: /mnt/reports/firewall-documentation.md
verbose: false
quiet: false
export:
  backup: true
```

### Machine-parseable output

```yaml
# ~/.opnDossier.yaml
format: json
json_output: true
logging:
  format: json
quiet: true
no_progress: true
```

## Troubleshooting

### The configuration file seems to be ignored

opnDossier falls back to defaults silently when it cannot read the file.

```bash
ls -la ~/.opnDossier.yaml              # does it exist?
chmod 600 ~/.opnDossier.yaml           # readable by you?
opndossier --verbose config show       # which file did it actually load?
```

If `config show` reports a different path than you expect, pass `--config` explicitly.

### Environment variables seem to be ignored

Three things go wrong most often:

1. **Missing or wrong prefix.** List what the shell is actually exporting with `env | grep OPNDOSSIER`.
2. **Missing underscore after the prefix.** `OPNDOSSIER_VERBOSE` is correct; `OPNDOSSIERVERBOSE` is not.
3. **Dot instead of underscore for nested keys.** `OPNDOSSIER_DISPLAY_WIDTH` is correct; `OPNDOSSIER_DISPLAY.WIDTH` is not a valid shell variable name.

### Configuration fails validation

`config validate` reports the offending field, the value it received, and the accepted values:

```bash
opndossier config validate --config /path/to/config.yaml
```

| Error                           | Accepted values                                                         |
| ------------------------------- | ----------------------------------------------------------------------- |
| invalid theme value             | `light`, `dark`, `auto`, `none`, `custom` (or empty for auto-detection) |
| invalid format                  | `markdown`, `md`, `json`, `yaml`, `yml`, `text`, `txt`, `html`, `htm`   |
| invalid log level               | `debug`, `info`, `warn`, `error`                                        |
| wrap width must be >= -1        | `-1` (auto), `0` (no wrap), or a positive integer                       |
| input file does not exist       | Check the path and its permissions                                      |
| output directory does not exist | Create it first with `mkdir -p`                                         |

### Seeing what opnDossier actually loaded

```bash
opndossier --verbose config show
```

This prints the configuration file path in use, the environment variables detected, and the final merged values — which is usually enough to explain any surprising behaviour.

## Related

- [Configuration Reference](configuration-reference.md) — every key, flag, and environment variable with types and defaults
- [`config` command](commands/config.md) — `init`, `show`, and `validate` in detail
- [Getting Started](getting-started.md) — first-run walkthrough
- [Common Workflows](workflows.md) — task-oriented recipes
