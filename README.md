🛡️ SOC Phishing & Investigation Toolkit

By VeerIsha Infrasec — IT Solutions Made Easy

A Python-based SOC investigation and alert triage toolkit designed to help security analysts investigate alerts using structured evidence and produce an analyst-ready investigation package.

🔎 Main Investigation Tool

soc_investigation_engine.py

This is the main SOC investigation application.

It can investigate security alerts using:

JSON

TXT

LOG

XML

CSV

EML

MSG

HTML

Raw SIEM / security events

Security-platform investigation URLs

🧠 Investigation Capabilities

The engine analyzes available evidence to identify:

Area

Evidence

🚨 Alert Context

Alert and incident context

👤 Users

Users and actors

🎯 Targets

Target users

💻 Assets

Devices and assets

🌐 Network

IP addresses, domains and URLs

📁 Files

File hashes

⚙️ Processes

Processes and command lines

🔗 Process Relationships

Parent/child process relationships

✉️ Email

Email headers and authentication results

📎 Attachments

Email/file attachments

🕒 Timeline

Event timelines

⚠️ Indicators

Suspicious indicators

✅ Legitimate Activity

Legitimate activity indicators

❓ Gaps

Missing investigation information

🎯 MITRE

MITRE ATT&CK techniques

📋 Investigation Output

The tool produces a complete SOC investigation package containing:

Executive summary

Plain-English explanation of what happened

User / actor analysis

Asset / device analysis

Network indicators

Process analysis

Timeline

Security findings

Legitimate activity indicators

Suspicious / malicious indicators

Missing information

Questions to ask the affected user

Questions for IT / system owners

MITRE ATT&CK mapping

Final verdict

Confidence level

Recommended severity

Recommended assignment / owner

Recommended remediation

SOC closure comments

Evidence register

Analyst notes

🎯 Verdicts

The engine can produce assessments such as:

Verdict

Meaning

FALSE POSITIVE

Alert determined to be false based on available evidence

BENIGN / EXPECTED ACTIVITY

Activity is legitimate or expected

TRUE POSITIVE

Evidence supports a genuine security incident

SUSPICIOUS / REQUIRES INVESTIGATION

Evidence indicates further investigation is required

INCONCLUSIVE

Available evidence is insufficient for a confident conclusion

Evidence-driven: The verdict is based on the evidence available to the engine. It does not intentionally fabricate missing information.

🔐 API Authentication

API credentials are not required for local evidence.

The tool does not request an API key when analyzing:

JSON

TXT

LOG

EML

MSG

HTML

XML

CSV

Pasted raw logs / events

For security-platform URLs, authentication may be requested only when authenticated access is required.

Supported Provider Classification

Rapid7

Microsoft Defender

CrowdStrike

Generic URLs

Security: API credentials should never be hardcoded into the source code or included in investigation reports.

🚀 Running the Tool

Interactive Mode

python soc_investigation_engine.py

🏢 About VeerIsha Infrasec

VeerIsha Infrasec provides IT, software, cybersecurity and infrastructure solutions.

IT Solutions Made Easy.

📌 Project

SOC Phishing & Investigation Toolkit

Developed and maintained by VeerIsha Infrasec.

The project is intended to support structured, evidence-driven SOC investigation and analyst triage, while keeping investigation conclusions grounded in the evidence available.
