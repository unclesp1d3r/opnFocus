# sanitize

The `sanitize` command redacts sensitive information from an OPNsense or pfSense configuration file while preserving its structure. The output is an XML file with passwords, keys, IP addresses, `system/authserver` LDAP values, and other secrets replaced by consistent replacements, so rule logic stays readable without exposing real credentials or addresses. How much topology survives depends on the mode: moderate keeps private addresses, aggressive replaces them with markers and produces a document for reading rather than a loadable configuration. Both OPNsense password fields (`<password>`) and pfSense bcrypt hashes (`<bcrypt-hash>`) are detected and redacted.

**When to use it:**

- Sharing configs with vendors, consultants, or support teams without exposing secrets
- Posting config excerpts in public forums or bug reports
- Creating sanitized test fixtures from production configs
- Compliance workflows that require redaction before archival or review

## Usage

```text
opndossier sanitize [flags] <config.xml>
```

## Flags

| Flag        | Short | Default    | Description                                            |
| ----------- | ----- | ---------- | ------------------------------------------------------ |
| `--mode`    | `-m`  | `moderate` | Sanitization mode: `aggressive`, `moderate`, `minimal` |
| `--output`  | `-o`  | stdout     | Output file path                                       |
| `--mapping` |       |            | Save a mapping file for reverse lookup (JSON)          |
| `--force`   |       | `false`    | Overwrite existing output file without prompt          |

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).

## Sanitization Modes

The `--mode` flag controls how aggressively the sanitizer redacts data. Each mode builds on the previous one -- `aggressive` redacts everything `moderate` does, plus more.

### Minimal

Redacts direct secrets and pseudonymizes sensitive `system/authserver` LDAP values. Use this in trusted environments where most network topology can remain visible but credentials and LDAP server details must not.

- Passwords, passphrases
- API keys, tokens, secrets
- Pre-shared keys (IPsec, WireGuard)
- Private keys
- SSH authorized keys
- SNMP community strings
- Sensitive `system/authserver` LDAP values
- Plugin enrollment credentials when present in raw XML (for example OPNsense NetBird `<setupKey>`)

### Moderate (default)

Adds network identity redaction on top of minimal. Use this for sharing with internal teams or contractors who should not see external-facing addresses.

Everything in minimal, plus:

- Public IP addresses (replaced with `[REDACTED-PUBLIC-IP-N]` markers)
- MAC addresses
- Email addresses

Private IPs (RFC 1918) and hostnames outside `system/authserver` are preserved, so internal network structure remains readable.

### Aggressive

Redacts everything for maximum safety. Use this before posting configs publicly or sharing with untrusted parties.

Everything in moderate, plus:

- Private IP addresses
- Hostnames and FQDNs
- Usernames (except system accounts like `root`, `admin`, `nobody`)
- Certificates
- Subnet/CIDR values
- VPN/tunnel endpoint addresses
- Cloud provider identifiers (account IDs, zone IDs)
- Public keys

### Referential Integrity

Across all modes, the sanitizer maintains referential integrity -- the same original value always maps to the same replacement value throughout the entire file. If `192.168.1.1` becomes `[REDACTED-PRIVATE-IP-1]`, every occurrence of `192.168.1.1` in the config is replaced with the same marker. This means firewall rules, routing tables, and DHCP scopes remain internally consistent.

Replacements come in two shapes, and the difference matters when reading a sanitized file:

| Value       | Replacement                   | Mistakable for a real value |
| ----------- | ----------------------------- | --------------------------- |
| Private IP  | `[REDACTED-PRIVATE-IP-1]`     | No                          |
| Public IP   | `[REDACTED-PUBLIC-IP-1]`      | No                          |
| MAC address | `XX:XX:XX:XX:XX:01`           | Partly, it keeps MAC shape  |
| Hostname    | `host-001.example.com`        | **Yes**                     |
| Username    | `user-001`                    | **Yes**                     |
| Domain      | `example.com`, `example2.com` | **Yes**                     |
| Email       | `user1@example.com`           | **Yes**                     |

Treat any hostname, username, domain or email in a sanitized file as redacted rather than real. Use the mapping file if you need to recover the original.

## Mapping File

The `--mapping` flag saves a JSON file that records every substitution the sanitizer made. This serves as a lookup table so you can trace a redacted value back to its original -- for example, when a colleague asks "what is `[REDACTED-PUBLIC-IP-1]` in the sanitized config?" you can look up the marker in the mapping file.

```bash
opndossier sanitize config.xml -o sanitized.xml --mapping mappings.json
```

The mapping file is organized by category:

```json
{
  "version": "1.0",
  "timestamp": "2026-03-12T10:30:00Z",
  "mode": "aggressive",
  "mappings": {
    "ip_addresses": {
      "192.168.1.1": "[REDACTED-PRIVATE-IP-1]",
      "192.168.1.100": "[REDACTED-PRIVATE-IP-2]",
      "203.0.113.50": "[REDACTED-PUBLIC-IP-1]"
    },
    "hostnames": {
      "fw01.example.com": "host-001.example.com"
    },
    "usernames": {
      "jdoe": "user-001"
    },
    "domains": {
      "example.com": "domain-001.example.com"
    },
    "mac_addresses": {
      "aa:bb:cc:dd:ee:ff": "00:00:5e:00:53:01"
    },
    "emails": {
      "admin@example.com": "user-001@example.com"
    },
    "authserver": {
      "name": {
        "corp-ldap": "authserver-001"
      },
      "host": {
        "ldap.corp.example.com": "ldap-001.example.invalid"
      },
      "ldap_port": {
        "636": "55001"
      },
      "ldap_bindpw": {
        "supersecret123": "BindPw-001-NotReal!"
      }
    }
  }
}
```

There is no built-in command to reverse a sanitization using the mapping file -- it is a reference for manual lookup. Keep the mapping file secure and do not share it alongside the sanitized config, as it contains the original values.

## Sanitize vs Redact

opnDossier offers two ways to hide sensitive data:

|               | `sanitize` command                                                               | `convert --redact`                                          |
| ------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Output**    | Valid OPNsense XML                                                               | Markdown, JSON, YAML, etc.                                  |
| **Scope**     | Full config file with consistent replacements                                    | Report fields replaced with `[REDACTED]`                    |
| **Traceable** | Yes, via mapping file (manual lookup)                                            | No                                                          |
| **Use case**  | Sharing a config file for inspection, and for topology analysis in moderate mode | Sharing a report where values do not need to be traced back |

## Examples

```bash
# Sanitize for public sharing (maximum redaction)
opndossier sanitize config.xml --mode aggressive -o config-sanitized.xml

# Sanitize with default moderate mode
opndossier sanitize config.xml -o sanitized.xml

# Save a mapping file for reverse lookup
opndossier sanitize config.xml -o sanitized.xml --mapping mappings.json

# Overwrite an existing output file without prompting
opndossier sanitize config.xml -o sanitized.xml --force
```

## Related

- [CLI Reference — `sanitize`](../../cli/opnDossier_sanitize.md) -- auto-generated exhaustive flag list
- [convert](convert.md) -- use `--redact` flag for inline redaction during conversion
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
