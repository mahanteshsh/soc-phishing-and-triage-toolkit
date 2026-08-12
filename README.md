# SOC Phishing & Investigation Toolkit

A Python-based SOC investigation and alert triage toolkit designed to help security analysts investigate alerts using structured evidence and produce an analyst-ready investigation package.

## Main Investigation Tool

### `soc_investigation_engine.py`

This is the **main SOC investigation application**.

It can investigate security alerts using:

- JSON
- TXT
- LOG
- XML
- CSV
- EML
- MSG
- HTML
- Raw SIEM/security events
- Security-platform investigation URLs

### Investigation Capabilities

The engine analyzes available evidence to identify:

- Alert and incident context
- Users and actors
- Target users
- Devices/assets
- IP addresses
- Domains
- URLs
- File hashes
- Processes
- Parent/child process relationships
- Process command lines
- Email headers and authentication results
- Attachments
- Event timelines
- Suspicious indicators
- Legitimate activity indicators
- Missing investigation information
- MITRE ATT&CK techniques

## Investigation Output

The tool produces a complete SOC investigation package containing:

1. Executive summary
2. Plain-English explanation of what happened
3. User/actor analysis
4. Asset/device analysis
5. Network indicators
6. Process analysis
7. Timeline
8. Security findings
9. Legitimate activity indicators
10. Suspicious/malicious indicators
11. Missing information
12. Questions to ask the affected user
13. Questions for IT/system owners
14. MITRE ATT&CK mapping
15. Final verdict
16. Confidence level
17. Recommended severity
18. Recommended assignment/owner
19. Recommended remediation
20. SOC closure comments
21. Evidence register
22. Analyst notes

## Verdicts

The engine can produce assessments such as:

- `FALSE POSITIVE`
- `BENIGN / EXPECTED ACTIVITY`
- `TRUE POSITIVE`
- `SUSPICIOUS / REQUIRES INVESTIGATION`
- `INCONCLUSIVE`

The verdict is based on the evidence available to the engine. It does not intentionally fabricate missing information.

## API Authentication

API credentials are **not required for local evidence**.

The tool does not request an API key when analyzing:

- JSON
- TXT
- LOG
- EML
- MSG
- HTML
- XML
- CSV
- Pasted raw logs/events

For security-platform URLs, authentication may be requested only when authenticated access is required.

Supported provider classification currently includes:

- Rapid7
- Microsoft Defender
- CrowdStrike
- Generic URLs

API credentials should never be hardcoded into the source code or included in investigation reports.

## Running the Tool

### Interactive mode

```bash
python soc_investigation_engine.py
