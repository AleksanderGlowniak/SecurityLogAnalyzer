# Security Log Analyzer

A lightweight security log analysis tool written in Java 21 that processes web server and authentication logs, detects suspicious activity, correlates related events, and produces actionable security findings.

## Overview

Security Log Analyzer is a command-line application designed to identify potential security incidents from multiple log sources.

The tool supports:

* Parsing multiple log formats
* Detection of common attack patterns
* Cross-log correlation
* Malformed log handling
* Configurable YAML-based rules
* Detailed console reporting
* Automated test suite

The project was intentionally implemented without frameworks to demonstrate core Java engineering skills, testability, and maintainability.

---

## Features

### Log Parsing

Supported log types:

* Apache-style web server logs
* Linux authentication logs (auth.log)

Features:

* Automatic parser detection
* Streaming file processing
* Graceful malformed-line handling
* Parse error reporting

### Security Detections

The analyzer currently detects:

| Detection            | Description                                         |
| -------------------- | --------------------------------------------------- |
| Brute Force Attack   | Multiple failed logins followed by success          |
| SQL Injection        | SQL injection payloads in requests                  |
| Directory Traversal  | Traversal attempts targeting sensitive files        |
| Reconnaissance       | Enumeration of administrative endpoints             |
| API Abuse            | High-volume API usage resulting in rate limiting    |
| Privilege Escalation | Sensitive privileged commands executed through sudo |

### Correlation

Related findings are merged into higher-confidence incidents.

Examples:

* SSH brute force + successful login
* Web login abuse + successful authentication
* Reconnaissance followed by exploitation attempts

### Reporting

Provides:

* Summary statistics
* Severity breakdown
* Detailed findings
* Parse error reporting

---

## Architecture

```text
Input Logs
    │
    ▼
AutoDetectParsingService
    │
    ▼
Normalized Events
    │
    ▼
Detection Engine
    │
    ▼
Incidents
    │
    ▼
Correlation Engine
    │
    ▼
Correlated Incidents
    │
    ▼
Console Reporter
```

### Main Components

```text
parser/
    LogParser
    WebServerLogParser
    AuthLogParser

detector/
    BruteForceDetector
    SQLInjectionDetector
    TraversalDetector
    ReconDetector
    ApiAbuseDetector
    PrivilegeEscalationDetector

service/
    AutoDetectParsingService
    DetectionService
    CorrelationEngine

report/
    StandardConsoleReporter
```

---

## Requirements

### Java

Java 21 (Temurin)

Verify installation:

```bash
java --version
```

Expected output:

```bash
openjdk 21
```

### Maven

Verify installation:

```bash
mvn -version
```

Expected output:

```bash
Apache Maven 3.9+
```

---

## Building the Project

Clone repository:

```bash
git clone https://github.com/<your-account>/security-log-analyzer.git
```

Navigate to project:

```bash
cd security-log-analyzer
```

Compile:

```bash
mvn clean compile
```

Run tests:

```bash
mvn test
```

Build executable jar:

```bash
mvn clean package
```

After successful build:

```text
target/
└── security-log-analyzer-1.0.0.jar
```

---

## Running the Analyzer

### Analyze Individual Files

```bash
java -jar target/security-log-analyzer-1.0.0.jar webserver.log auth.log
```

### Analyze Multiple Log Files

Linux / macOS:

```bash
java -jar target/security-log-analyzer-1.0.0.jar *.log
```

Windows PowerShell:

```powershell
java -jar target/security-log-analyzer-1.0.0.jar *.log
```

### Example

```bash
java -jar target/security-log-analyzer-1.0.0.jar \
    samples/webserver.log \
    samples/auth.log
```

---

## Configuration

Detection rules are defined in:

```text
src/main/resources/rules.yaml
```

Example:

```yaml
failedLoginThreshold: 4

adminProbeThreshold: 3

requestBurstThreshold: 5

sqlInjectionPatterns:
  - UNION SELECT
  - DROP TABLE

traversalPatterns:
  - ../
  - /etc/passwd

sensitivePaths:
  - /admin
  - /phpmyadmin
  - /wp-admin

sensitiveCommands:
  - /etc/shadow
```

Changing configuration does not require code changes.

---

## Testing

Execute full test suite:

```bash
mvn test
```

Execute specific test:

```bash
mvn test -Dtest=BruteForceDetectorTest
```

Generate coverage report:

```bash
mvn verify
```

Test categories:

* Parser Tests
* Detector Tests
* Correlation Tests
* Integration Tests
* Malformed Input Tests

---

## Error Handling

Malformed entries do not terminate processing.

Example malformed entry:

```text
[MALFORMED ENTRY - system restart
```

Result:

```text
Parse Errors : 1
```

The remaining log entries continue to be processed.

---

## Design Decisions

### Why Normalized Events?

Detectors operate on a common event model rather than raw log formats.

Benefits:

* Decouples parsers from detectors
* Easier testing
* Easier extension

### Why YAML Configuration?

Rules can be modified without recompiling.

Benefits:

* Operational flexibility
* Easier tuning
* Better maintainability

### Why Correlation?

Correlation reduces alert fatigue by combining related findings into higher-confidence incidents.

---

## Future Enhancements

Potential production improvements:

* JSON reporting
* CSV export
* SIEM integration
* Real-time tailing mode
* Parallel processing
* Time-window correlation
* Additional log formats
* MITRE ATT&CK mapping

---

## AI Usage

This project was developed with AI assistance.

The complete AI conversation transcript is included in:

```text
docs/ai-conversation.md
```

---

## License

For technical assessment purposes only.
