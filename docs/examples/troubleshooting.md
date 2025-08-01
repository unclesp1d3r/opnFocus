# Troubleshooting and Debugging Examples

This guide covers common issues, error handling, and debugging techniques for opnFocus.

## Common Error Scenarios

### XML Parsing Errors

#### Invalid XML Structure

```bash
# Error: Invalid XML syntax
opnFocus convert invalid-config.xml
# Output: failed to parse XML from invalid-config.xml: XML syntax error on line 42

# Debug XML issues
opnFocus --verbose convert invalid-config.xml

# Validate XML syntax first
xmllint --noout invalid-config.xml
```

#### Malformed OPNsense Configuration

```bash
# Error: Missing required elements
opnFocus convert malformed-config.xml
# Output: validation error at opnsense.system.hostname: hostname is required

# Debug with verbose output
opnFocus --verbose convert malformed-config.xml

# Check specific validation errors
opnFocus validate malformed-config.xml
```

### File Permission Issues

```bash
# Error: Permission denied
opnFocus convert /root/config.xml
# Output: failed to open file /root/config.xml: permission denied

# Solutions:
# 1. Copy file to accessible location
sudo cp /root/config.xml ./config.xml
opnFocus convert config.xml

# 2. Change file permissions (if appropriate)
sudo chmod 644 /root/config.xml

# 3. Run with appropriate permissions
sudo opnFocus convert /root/config.xml
```

### Configuration Validation Errors

```bash
# Error: Conflicting flags
opnFocus --verbose --quiet convert config.xml
# Output: verbose and quiet options are mutually exclusive

# Error: Invalid log level
opnFocus --log_level=trace convert config.xml
# Output: invalid log level 'trace', must be one of: debug, info, warn, error

# Error: Invalid output format
opnFocus convert config.xml -f txt
# Output: unsupported format: txt
```

## Debug Techniques

### Verbose Debugging

```bash
# Enable verbose output for detailed debugging
opnFocus --verbose convert config.xml

# Enable debug logging
opnFocus --log_level=debug convert config.xml

# Combine verbose and debug
opnFocus --verbose --log_level=debug convert config.xml
```

### JSON Logging for Analysis

```bash
# Capture detailed logs in JSON format
opnFocus --log_format=json --log_level=debug convert config.xml > debug.log 2>&1

# Analyze logs with jq
jq '.level' debug.log | sort | uniq -c

# Extract error messages
jq 'select(.level == "error") | .msg' debug.log

# Extract timing information
jq 'select(.msg | contains("duration"))' debug.log
```

### Step-by-Step Debugging

```bash
# 1. Validate configuration first
opnFocus validate config.xml

# 2. Test basic conversion
opnFocus convert config.xml

# 3. Test with specific format
opnFocus convert config.xml -f json

# 4. Test with specific sections
opnFocus convert config.xml --section system

# 5. Test with custom template
opnFocus convert config.xml --template-dir ./custom-templates
```

## Common Issues and Solutions

### Issue 1: Large File Processing

**Symptoms:**

- Slow processing
- High memory usage
- Timeout errors

**Solutions:**

```bash
# Use streaming mode (built-in)
opnFocus convert large-config.xml

# Monitor memory usage
/usr/bin/time -v opnFocus convert large-config.xml

# Process in sections
opnFocus convert large-config.xml --section system,interfaces
opnFocus convert large-config.xml --section firewall,nat
```

### Issue 2: Template Rendering Problems

**Symptoms:**

- Template not found errors
- Incorrect output formatting
- Missing sections

**Solutions:**

```bash
# Check template directory
ls -la ~/.opnFocus/templates/

# Use built-in templates
opnFocus convert config.xml --template standard

# Debug template rendering
opnFocus --verbose convert config.xml --template-dir ./custom-templates

# Check template syntax
opnFocus convert config.xml --template-dir ./custom-templates --log_level=debug
```

### Issue 3: Plugin Loading Issues

**Symptoms:**

- Plugin not found errors
- Plugin execution failures
- Missing compliance checks

**Solutions:**

```bash
# Check available plugins
opnFocus convert config.xml --plugins stig,sans

# Test individual plugins
opnFocus convert config.xml --plugins stig
opnFocus convert config.xml --plugins sans

# Debug plugin loading
opnFocus --verbose convert config.xml --plugins stig,sans
```

### Issue 4: Output File Issues

**Symptoms:**

- File not created
- Permission errors
- Overwrite prompts

**Solutions:**

```bash
# Check output directory permissions
ls -la /path/to/output/directory

# Force overwrite
opnFocus convert config.xml -o output.md --force

# Use different output location
opnFocus convert config.xml -o /tmp/output.md

# Check disk space
df -h /path/to/output/directory
```

## Advanced Debugging

### Memory Profiling

```bash
# Run with memory profiling
go tool pprof -http=:8080 $(which opnFocus) mem.prof

# Generate memory profile
opnFocus convert config.xml -o output.md
# (Memory profile is automatically generated for large files)
```

### Performance Analysis

```bash
# Measure execution time
time opnFocus convert config.xml

# Profile CPU usage
go tool pprof -http=:8080 $(which opnFocus) cpu.prof

# Analyze specific operations
opnFocus --log_level=debug convert config.xml 2>&1 | grep "duration"
```

### Network Debugging (if applicable)

```bash
# Check for network calls (should be none in offline mode)
strace -e trace=network opnFocus convert config.xml

# Monitor file system access
strace -e trace=file opnFocus convert config.xml

# Check for external dependencies
ldd $(which opnFocus)
```

## Error Recovery

### Recovering from Validation Errors

```bash
# 1. Identify specific validation errors
opnFocus validate config.xml

# 2. Fix common issues
# Missing hostname
sed -i 's/<hostname><\/hostname>/<hostname>firewall<\/hostname>/' config.xml

# Invalid IP address
sed -i 's/<ipaddr>256.256.256.256<\/ipaddr>/<ipaddr>192.168.1.1<\/ipaddr>/' config.xml

# 3. Re-validate
opnFocus validate config.xml

# 4. Convert if valid
opnFocus convert config.xml
```

### Recovering from Template Errors

```bash
# 1. Check template syntax
opnFocus convert config.xml --template-dir ./templates --log_level=debug

# 2. Use fallback template
opnFocus convert config.xml --template standard

# 3. Create minimal template
cat > minimal-template.md.tmpl << EOF
# Configuration Report
{{.System.Hostname}}
EOF

# 4. Test with minimal template
opnFocus convert config.xml --template-dir ./templates
```

### Recovering from Plugin Errors

```bash
# 1. Check plugin availability
opnFocus convert config.xml --plugins stig

# 2. Run without plugins
opnFocus convert config.xml

# 3. Run with specific plugins only
opnFocus convert config.xml --plugins stig

# 4. Debug plugin execution
opnFocus --verbose convert config.xml --plugins stig --log_level=debug
```

## Diagnostic Scripts

### Configuration Health Check

```bash
#!/bin/bash
# config-health-check.sh

CONFIG_FILE="$1"
LOG_FILE="health-check.log"

echo "Configuration Health Check for $CONFIG_FILE" > "$LOG_FILE"
echo "Started at $(date)" >> "$LOG_FILE"

# Check file existence
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: File not found: $CONFIG_FILE" >> "$LOG_FILE"
    exit 1
fi

# Check file size
FILE_SIZE=$(stat -c%s "$CONFIG_FILE")
echo "File size: $FILE_SIZE bytes" >> "$LOG_FILE"

# Check file permissions
FILE_PERMS=$(stat -c%a "$CONFIG_FILE")
echo "File permissions: $FILE_PERMS" >> "$LOG_FILE"

# Validate XML syntax
if xmllint --noout "$CONFIG_FILE" 2>/dev/null; then
    echo "XML syntax: VALID" >> "$LOG_FILE"
else
    echo "XML syntax: INVALID" >> "$LOG_FILE"
    exit 1
fi

# Run opnFocus validation
if opnFocus validate "$CONFIG_FILE" >> "$LOG_FILE" 2>&1; then
    echo "opnFocus validation: PASSED" >> "$LOG_FILE"
else
    echo "opnFocus validation: FAILED" >> "$LOG_FILE"
    exit 1
fi

# Test conversion
if opnFocus convert "$CONFIG_FILE" -o /tmp/test.md >> "$LOG_FILE" 2>&1; then
    echo "Conversion test: PASSED" >> "$LOG_FILE"
    rm -f /tmp/test.md
else
    echo "Conversion test: FAILED" >> "$LOG_FILE"
    exit 1
fi

echo "Health check completed successfully at $(date)" >> "$LOG_FILE"
```

### Performance Diagnostic

```bash
#!/bin/bash
# performance-diagnostic.sh

CONFIG_FILE="$1"
RESULTS_FILE="performance-results.log"

echo "Performance Diagnostic for $CONFIG_FILE" > "$RESULTS_FILE"
echo "Started at $(date)" >> "$RESULTS_FILE"

# Measure validation time
echo "Measuring validation time..." >> "$RESULTS_FILE"
VALIDATION_TIME=$(/usr/bin/time -f "%e" opnFocus validate "$CONFIG_FILE" 2>&1)
echo "Validation time: ${VALIDATION_TIME}s" >> "$RESULTS_FILE"

# Measure conversion time
echo "Measuring conversion time..." >> "$RESULTS_FILE"
CONVERSION_TIME=$(/usr/bin/time -f "%e" opnFocus convert "$CONFIG_FILE" -o /tmp/test.md 2>&1)
echo "Conversion time: ${CONVERSION_TIME}s" >> "$RESULTS_FILE"

# Measure memory usage
echo "Measuring memory usage..." >> "$RESULTS_FILE"
MEMORY_USAGE=$(/usr/bin/time -f "%M" opnFocus convert "$CONFIG_FILE" -o /tmp/test.md 2>&1)
echo "Memory usage: ${MEMORY_USAGE}KB" >> "$RESULTS_FILE"

# Clean up
rm -f /tmp/test.md

echo "Performance diagnostic completed at $(date)" >> "$RESULTS_FILE"
```

### Error Pattern Analysis

```bash
#!/bin/bash
# error-pattern-analysis.sh

LOG_FILE="$1"
ANALYSIS_FILE="error-analysis.log"

echo "Error Pattern Analysis for $LOG_FILE" > "$ANALYSIS_FILE"

# Extract error messages
echo "=== ERROR MESSAGES ===" >> "$ANALYSIS_FILE"
grep -i "error\|failed\|invalid" "$LOG_FILE" >> "$ANALYSIS_FILE"

# Count error types
echo "=== ERROR COUNTS ===" >> "$ANALYSIS_FILE"
grep -i "error\|failed\|invalid" "$LOG_FILE" | sort | uniq -c | sort -nr >> "$ANALYSIS_FILE"

# Extract timing information
echo "=== TIMING INFORMATION ===" >> "$ANALYSIS_FILE"
grep -i "duration\|time\|elapsed" "$LOG_FILE" >> "$ANALYSIS_FILE"

# Extract validation errors
echo "=== VALIDATION ERRORS ===" >> "$ANALYSIS_FILE"
grep -i "validation" "$LOG_FILE" >> "$ANALYSIS_FILE"

echo "Error pattern analysis completed" >> "$ANALYSIS_FILE"
```

## Best Practices for Troubleshooting

### 1. Systematic Approach

```bash
# Always start with validation
opnFocus validate config.xml

# Test basic functionality
opnFocus convert config.xml

# Add complexity gradually
opnFocus convert config.xml -f json
opnFocus convert config.xml --mode blue
opnFocus convert config.xml --plugins stig
```

### 2. Logging Strategy

```bash
# Use appropriate log levels
opnFocus --log_level=info convert config.xml      # Normal operation
opnFocus --log_level=debug convert config.xml     # Detailed debugging
opnFocus --log_level=warn convert config.xml      # Warnings only

# Use structured logging for automation
opnFocus --log_format=json convert config.xml > logs.json
```

### 3. Error Handling in Scripts

```bash
#!/bin/bash
# robust-script.sh

set -e  # Exit on any error

# Function to handle errors
handle_error() {
    local exit_code=$?
    echo "Error occurred in line $1, exit code: $exit_code"

    # Log error details
    echo "$(date): Error in $0 at line $1, exit code: $exit_code" >> error.log

    # Send notification if needed
    # curl -X POST -H 'Content-type: application/json' \
    #     --data "{\"text\":\"Error in opnFocus script\"}" \
    #     "$WEBHOOK_URL"

    exit $exit_code
}

# Set error handler
trap 'handle_error $LINENO' ERR

# Your script logic here
opnFocus validate config.xml
opnFocus convert config.xml -o output.md
```

### 4. Environment Isolation

```bash
# Test in clean environment
env -i PATH=/usr/bin:/bin opnFocus convert config.xml

# Test with minimal configuration
opnFocus --config /dev/null convert config.xml

# Test with specific environment variables
OPNFOCUS_LOG_LEVEL=debug opnFocus convert config.xml
```

---

**Next Steps:**

- For advanced configuration, see [Advanced Configuration](advanced-configuration.md)
- For basic documentation, see [Basic Documentation](basic-documentation.md)
- For audit and compliance, see [Audit and Compliance](audit-compliance.md)
