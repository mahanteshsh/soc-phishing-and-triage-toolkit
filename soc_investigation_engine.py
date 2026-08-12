#!/usr/bin/env python3
"""
SOC Investigation & Alert Triage Engine
========================================

A defensive, evidence-first SOC investigation assistant.

Supported local evidence:
    JSON, TXT, LOG, XML, HTML/HTM, EML, MSG (best-effort)

Supported remote workflow:
    URLs are classified and may optionally use a provider-specific API.
    API credentials are requested ONLY when authenticated access is needed.

Design principles:
    - Evidence first; no verdict from a single keyword.
    - No fabricated API results, identities, reputation, or user confirmation.
    - Suspicious evidence is parsed, not executed.
    - API secrets are never written to reports or investigation JSON.
    - Every major finding should identify its evidence basis.
    - Local evidence works without API credentials.

Run:
    python soc_investigation_engine.py
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
import email
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
import getpass
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import textwrap
import traceback
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


APP_NAME = "SOC Investigation & Alert Triage Engine"
APP_VERSION = "2.0.0"

REPORT_DIR = Path("soc_investigations")
LOG_DIR = REPORT_DIR / "logs"
REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=str(LOG_DIR / "engine.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
LOGGER = logging.getLogger(APP_NAME)

UNKNOWN = "Not Available"
MAX_TEXT = 12000
MAX_ITEMS = 5000


# ---------------------------------------------------------------------------
# Existing project concepts preserved and expanded.
# ---------------------------------------------------------------------------

EVENT_DICTIONARY = {
    "powershell": {
        "title": "PowerShell Script / Remote Command Execution",
        "example": "Windows PowerShell was used to execute commands or automation.",
        "why_fp": "An administrator, endpoint-management tool, or deployment system may legitimately use PowerShell.",
        "why_tp": "Attackers commonly abuse PowerShell to execute commands, download payloads, or perform discovery.",
        "impact": "PowerShell can change system settings, execute code, and access files or network resources.",
    },
    "member_added_to_security_group": {
        "title": "User Added to Security / Privileged Group",
        "example": "An account received membership in a security-sensitive group.",
        "why_fp": "This may be legitimate onboarding, access provisioning, or approved administration.",
        "why_tp": "An attacker may add an account to a privileged group for persistence or privilege escalation.",
        "impact": "The target account may receive additional permissions.",
    },
    "createservicespecificcredential": {
        "title": "Created Git / Code Access Credential",
        "example": "A credential or token was created for application or code access.",
        "why_fp": "A developer or automation workflow may legitimately create credentials.",
        "why_tp": "An attacker may create credentials to establish persistence or access repositories.",
        "impact": "A new credential may provide persistent access to protected resources.",
    },
    "cmdkey.exe": {
        "title": "Windows Credential Store Access",
        "example": "cmdkey.exe was used to inspect or manage stored credentials.",
        "why_fp": "An administrator may use it during troubleshooting.",
        "why_tp": "Credential discovery can support lateral movement or privilege escalation.",
        "impact": "Stored credential information may be exposed or manipulated.",
    },
}


SUSPICIOUS_PROCESS_RELATIONSHIPS = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("winword.exe", "rundll32.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "wscript.exe"),
    ("excel.exe", "mshta.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("browser", "powershell.exe"),
    ("browser", "cmd.exe"),
}

LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "cscript.exe",
    "wscript.exe",
    "msiexec.exe",
    "installutil.exe",
}

SENSITIVE_COMMAND_PATTERNS = [
    ("encoded PowerShell command", re.compile(r"(?i)(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}")),
    ("PowerShell download activity", re.compile(r"(?i)(invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer|downloadstring|downloadfile)")),
    ("remote URL in command", re.compile(r"https?://[^\s\"'<>]+", re.I)),
    ("credential-related command", re.compile(r"(?i)(sekurlsa|mimikatz|lsass|vaultcmd|cmdkey|credential|password|sam\b|ntds\.dit)")),
    ("persistence-related command", re.compile(r"(?i)(schtasks|scheduled task|new-service|sc\.exe\s+create|run\s*keys?|startup)")),
    ("defense-evasion command", re.compile(r"(?i)(disable.*defender|set-mppreference|exclusionpath|amsi|bypass|uninstall.*security)")),
    ("discovery command", re.compile(r"(?i)(whoami|ipconfig|systeminfo|net\s+user|net\s+group|nltest|tasklist|qwinsta|arp\s+-a)")),
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    evidence_id: str
    source_type: str
    source_name: str
    description: str
    content_hash_sha256: Optional[str] = None
    acquisition: str = "Provided by analyst"
    status: str = "available"
    notes: str = ""


@dataclass
class ProcessRecord:
    name: str = UNKNOWN
    pid: str = UNKNOWN
    parent_pid: str = UNKNOWN
    parent_name: str = UNKNOWN
    path: str = UNKNOWN
    command_line: str = UNKNOWN
    user: str = UNKNOWN
    start_time: str = UNKNOWN
    end_time: str = UNKNOWN
    hash_sha256: str = UNKNOWN
    publisher: str = UNKNOWN
    children: List[str] = field(default_factory=list)


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    description: str
    source: str
    confidence: str = "Medium"


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    evidence_type: str
    description: str
    evidence_refs: List[str] = field(default_factory=list)
    implication: str = ""
    status: str = "Open"


@dataclass
class Investigation:
    investigation_id: str
    created_at: str
    analyst: str = UNKNOWN
    alert_id: str = UNKNOWN
    detection_source: str = UNKNOWN
    alert_name: str = UNKNOWN
    severity: str = UNKNOWN
    raw_sources: List[str] = field(default_factory=list)

    actors: List[str] = field(default_factory=list)
    target_users: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)

    processes: List[ProcessRecord] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    raw_events: List[Dict[str, Any]] = field(default_factory=list)
    analyst_notes: List[str] = field(default_factory=list)
    user_questions: List[Dict[str, str]] = field(default_factory=list)
    it_questions: List[Dict[str, str]] = field(default_factory=list)

    legitimate_indicators: List[str] = field(default_factory=list)
    malicious_indicators: List[str] = field(default_factory=list)
    missing_information: List[str] = field(default_factory=list)

    verdict: str = "INCONCLUSIVE"
    confidence: str = "Low"
    recommended_severity: str = "Informational"
    recommended_owner: str = "SOC / SecOps"
    verdict_reason: str = ""
    remediation: List[str] = field(default_factory=list)
    mitre: List[Dict[str, str]] = field(default_factory=list)
    closure_comments: str = ""


# ---------------------------------------------------------------------------
# Generic utilities
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def investigation_id() -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"INV-{stamp}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def clean(value: Any, default: str = UNKNOWN) -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    text = str(value).strip()
    return text if text and text.lower() not in {"n/a", "na", "null", "none", "-"} else default


def unique(values: Iterable[str], limit: int = 1000) -> List[str]:
    out, seen = [], set()
    for v in values:
        v = clean(v)
        if v == UNKNOWN:
            continue
        key = v.lower()
        if key not in seen:
            seen.add(key)
            out.append(v)
            if len(out) >= limit:
                break
    return out


def flatten_dict(obj: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            yield p, v
            yield from flatten_dict(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:MAX_ITEMS]):
            yield from flatten_dict(v, f"{prefix}[{i}]")


def safe_json_loads(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except Exception:
        pass

    # Some exported logs contain JSON with escaped backslashes.
    try:
        return json.loads(text.replace("\\", "\\\\"))
    except Exception:
        return None


def redact_secret(text: str) -> str:
    if not text:
        return text
    patterns = [
        r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+",
        r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+",
        r"(?i)(token\s*[:=]\s*)[^\s,;]+",
    ]
    result = text
    for p in patterns:
        result = re.sub(p, r"\1[REDACTED]", result)
    return result


def sanitize_command_line(cmd: str) -> str:
    cmd = clean(cmd)
    if cmd == UNKNOWN:
        return UNKNOWN
    # Do not expose potentially long secrets/tokens in reports.
    cmd = re.sub(r"(?i)(-token|-apikey|api[_-]?key|password)\s+[^\s]+", r"\1 [REDACTED]", cmd)
    if len(cmd) > 500:
        cmd = cmd[:497] + "..."
    return cmd


def extract_urls(text: str) -> List[str]:
    return unique(re.findall(r"https?://[^\s<>'\"\])}]+", text or "", re.I), 200)


def extract_ips(text: str) -> List[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    good = []
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            good.append(ip)
        except ValueError:
            continue
    return unique(good, 200)


def extract_hashes(text: str) -> List[str]:
    return unique(
        re.findall(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b", text or ""),
        500,
    )


def extract_domains(text: str) -> List[str]:
    urls = extract_urls(text)
    domains = []
    for u in urls:
        try:
            d = urlparse(u).hostname
            if d:
                domains.append(d.lower())
        except Exception:
            pass
    # Also find domain-like strings, but avoid obvious filenames.
    domains += re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", text or "")
    return unique(domains, 500)


# ---------------------------------------------------------------------------
# Existing-style extractors, expanded
# ---------------------------------------------------------------------------

def extract_user_universal(raw_text: str, data_dict: Any = None) -> str:
    keys = {
        "user", "source_user", "sourceuser", "username", "account",
        "subjectusername", "targetusername", "accountname", "caller",
        "actor", "target_user", "target_member", "target_account",
        "userprincipalname", "upn", "initiatinguser", "initiating_user",
    }
    candidates = []

    if data_dict is not None:
        for key, value in flatten_dict(data_dict):
            leaf = key.split(".")[-1].replace("[", "").replace("]", "").lower()
            if leaf in keys:
                if isinstance(value, str):
                    candidates.append(value)
                elif isinstance(value, dict):
                    for subkey in ("name", "username", "value", "id", "userPrincipalName"):
                        if subkey in value:
                            candidates.append(clean(value[subkey]))

    xml_matches = re.findall(
        r'<Data\s+Name=["\'](?:SubjectUserName|TargetUserName|User|AccountName|SourceUser|TargetUser)["\']>\s*([^<]+)\s*</Data>',
        raw_text,
        re.I,
    )
    candidates.extend(xml_matches)

    candidates.extend(
        re.findall(r"[Cc]:[\\/]+Users[\\/]+([^\\/\r\n\"'\s;,]+)", raw_text)
    )

    text_matches = re.findall(
        r"(?:source_?user|target_?user|subject_?username|target_?username|"
        r"account\s*name|user\s*account|user\s*name|actor|caller|user)"
        r"[\s:=]+([A-Za-z0-9._\\@-]+)",
        re.sub(r"<[^>]+>", " ", raw_text),
        re.I,
    )
    candidates.extend(text_matches)

    candidates = unique(candidates, 100)
    ignored = {"system", "local service", "network service", "unknown user"}
    for candidate in candidates:
        if candidate.lower() not in ignored and candidate.lower() not in {"is", "the", "a"}:
            return candidate
    return UNKNOWN


def extract_process_info(data: Any, raw_text: str) -> Tuple[str, str]:
    process_name = UNKNOWN
    command = UNKNOWN

    if isinstance(data, dict):
        for key, value in flatten_dict(data):
            leaf = key.split(".")[-1].lower()
            if leaf in {"process_name", "processname", "image", "executable", "exe"} and process_name == UNKNOWN:
                process_name = clean(value)
            if leaf in {"cmdline", "commandline", "command_line", "process_command_line"} and command == UNKNOWN:
                command = clean(value)

    xml_image = re.search(r'<Data\s+Name=["\']Image["\']>\s*([^<]+)\s*</Data>', raw_text, re.I)
    xml_cmd = re.search(r'<Data\s+Name=["\']CommandLine["\']>\s*([^<]+)\s*</Data>', raw_text, re.I)
    if process_name == UNKNOWN and xml_image:
        process_name = xml_image.group(1).strip()
    if command == UNKNOWN and xml_cmd:
        command = xml_cmd.group(1).strip()

    if process_name == UNKNOWN:
        m = re.search(r"(?i)\b([A-Za-z0-9_.-]+\.exe)\b", raw_text)
        if m:
            process_name = m.group(1)

    return process_name, sanitize_command_line(command)


def extract_action(data: Any, raw_text: str, process_name: str, cmd_line: str) -> str:
    if isinstance(data, dict):
        for key, value in flatten_dict(data):
            leaf = key.split(".")[-1].lower()
            if leaf in {"action", "eventname", "event_type", "eventtype", "activity", "operation"}:
                if isinstance(value, (str, int, float)):
                    return clean(value)

    m = re.search(r'<Data\s+Name=["\']EventName["\']>\s*([^<]+)\s*</Data>', raw_text, re.I)
    if m:
        return m.group(1).strip()

    if "invoke-webrequest" in cmd_line.lower():
        return "Process Execution: Remote File Download (Invoke-WebRequest)"
    if process_name != UNKNOWN:
        return f"Process Execution ({process_name})"
    return UNKNOWN


def extract_target_object(data: Any, raw_text: str) -> str:
    keys = {
        "target_user", "target_group", "target_member", "target_account",
        "target_object", "target_name", "group_name", "target",
        "hostname", "host", "device", "computer", "computername",
        "dns_domain", "ou",
    }
    candidates = []
    if data is not None:
        for key, value in flatten_dict(data):
            if key.split(".")[-1].lower() in keys:
                if isinstance(value, str):
                    candidates.append(value)
                elif isinstance(value, dict):
                    for k in ("name", "username", "group_name", "id", "hostname"):
                        if k in value:
                            candidates.append(clean(value[k]))
    candidates.extend(re.findall(
        r'<Data\s+Name=["\'](?:TargetUserName|TargetGroup|WorkstationName|Computer)["\']>\s*([^<]+)\s*</Data>',
        raw_text, re.I))
    return unique(candidates, 50)[0] if unique(candidates, 50) else UNKNOWN


def get_event_details(raw_action: str, cmd_line: str) -> Dict[str, str]:
    combined = f"{raw_action} {cmd_line}".lower()
    for key, info in EVENT_DICTIONARY.items():
        if key in combined:
            return info
    return {
        "title": f"Observed action '{raw_action}'",
        "example": "A security-relevant event was recorded.",
        "why_fp": "The activity may have a legitimate operational explanation.",
        "why_tp": "The activity could represent unauthorized or malicious behavior.",
        "impact": "The actual impact depends on the affected account, device, process, and follow-on activity.",
    }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

class SafeHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts: List[str] = []
        self.urls: List[str] = []
        self.forms: List[str] = []
        self.scripts: int = 0
        self.iframes: int = 0

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag.lower() == "script":
            self.scripts += 1
        if tag.lower() == "iframe":
            self.iframes += 1
        if tag.lower() == "form":
            self.forms.append(str(attrs_d))
        for key in ("href", "src", "action"):
            if key in attrs_d and attrs_d[key]:
                self.urls.append(attrs_d[key])

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.text_parts.append(text)


def parse_html(raw: str) -> Dict[str, Any]:
    parser = SafeHTMLParser()
    try:
        parser.feed(raw)
    except Exception as exc:
        LOGGER.warning("HTML parse issue: %s", exc)
    text = "\n".join(parser.text_parts)
    return {
        "text": text,
        "urls": extract_urls(raw) + unique(
            [u for u in parser.urls if u.startswith(("http://", "https://"))], 200
        ),
        "forms": parser.forms,
        "scripts": parser.scripts,
        "iframes": parser.iframes,
    }


def parse_email_bytes(raw: bytes, filename: str) -> Dict[str, Any]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {k: str(v) for k, v in msg.items()}
    body_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            ctype = part.get_content_type()
            if "attachment" in disposition:
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": part.get_filename() or UNKNOWN,
                    "content_type": ctype,
                    "size": len(payload),
                    "sha256": sha256_bytes(payload) if payload else UNKNOWN,
                })
            elif ctype in {"text/plain", "text/html"}:
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_parts.append(payload.decode(errors="ignore"))
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append(raw.decode(errors="ignore"))

    return {
        "filename": filename,
        "headers": headers,
        "body": "\n".join(map(str, body_parts)),
        "attachments": attachments,
        "urls": extract_urls("\n".join(body_parts)),
    }


def parse_msg_best_effort(path: Path) -> Dict[str, Any]:
    """
    MSG is a Microsoft Compound File format. Full Outlook MSG extraction is
    optional. We safely attempt a text extraction from raw bytes. We never
    execute embedded content.
    """
    raw = path.read_bytes()
    text = raw.decode("utf-16-le", errors="ignore") + "\n" + raw.decode("utf-8", errors="ignore")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)
    return {
        "filename": path.name,
        "body": text[:MAX_TEXT],
        "urls": extract_urls(text),
        "note": "MSG parsed using best-effort safe text extraction. Full MAPI property extraction is not enabled.",
    }


def parse_file(path: Path) -> Tuple[str, str, Any]:
    suffix = path.suffix.lower()
    raw = path.read_bytes()

    if suffix == ".eml":
        return "EMAIL", raw.decode("utf-8", errors="ignore"), parse_email_bytes(raw, path.name)

    if suffix == ".msg":
        parsed = parse_msg_best_effort(path)
        return "MSG", parsed.get("body", ""), parsed

    text = raw.decode("utf-8", errors="ignore")

    if suffix in {".html", ".htm"}:
        return "HTML", text, parse_html(text)

    if suffix in {".json", ".txt", ".log", ".xml", ".csv"}:
        data = safe_json_loads(text) if suffix == ".json" else None
        return suffix[1:].upper(), text, data

    # Detect email headers even without .eml.
    if is_email_header(text):
        parsed = parse_email_text(text)
        return "EMAIL", text, parsed

    return "TEXT", text, None


def is_email_header(raw_content: str) -> bool:
    keywords = [
        "Received:", "From:", "Subject:", "Return-Path:",
        "Authentication-Results:", "Delivered-To:",
    ]
    return sum(1 for kw in keywords if kw.lower() in raw_content.lower()) >= 2


def parse_email_text(raw_content: str) -> Dict[str, Any]:
    msg = Parser(policy=policy.default).parsestr(raw_content)
    headers = {k: str(v) for k, v in msg.items()}
    return {
        "headers": headers,
        "body": str(msg.get_body(preferencelist=("plain", "html")).get_content())
        if msg.get_body(preferencelist=("plain", "html")) else "",
        "urls": extract_urls(raw_content),
        "attachments": [],
    }


# ---------------------------------------------------------------------------
# Normalization / evidence collection
# ---------------------------------------------------------------------------

def add_evidence(inv: Investigation, source_type: str, source_name: str,
                  description: str, content_hash: Optional[str] = None,
                  status: str = "available", notes: str = "") -> str:
    eid = f"E{len(inv.evidence) + 1:04d}"
    inv.evidence.append(EvidenceItem(
        evidence_id=eid,
        source_type=source_type,
        source_name=source_name,
        description=description,
        content_hash_sha256=content_hash,
        status=status,
        notes=notes,
    ))
    return eid


def collect_common_indicators(inv: Investigation, raw_text: str, data: Any):
    inv.ips = unique(inv.ips + extract_ips(raw_text), 500)
    inv.urls = unique(inv.urls + extract_urls(raw_text), 500)
    inv.domains = unique(inv.domains + extract_domains(raw_text), 500)
    inv.hashes = unique(inv.hashes + extract_hashes(raw_text), 500)

    user = extract_user_universal(raw_text, data)
    if user != UNKNOWN:
        inv.actors = unique(inv.actors + [user])

    target = extract_target_object(data, raw_text)
    if target != UNKNOWN:
        # Avoid assuming every target is an asset.
        inv.assets = unique(inv.assets + [target])


def collect_timestamps(inv: Investigation, data: Any, source_name: str):
    if data is None:
        return

    timestamp_keys = {
        "timestamp", "time", "eventtime", "event_time", "created",
        "created_at", "creationtime", "starttime", "datetime",
    }

    candidates = []
    for key, value in flatten_dict(data):
        leaf = key.split(".")[-1].lower()
        if leaf in timestamp_keys and isinstance(value, (str, int, float)):
            candidates.append(str(value))

    for ts in unique(candidates, 100):
        inv.timeline.append(TimelineEvent(
            timestamp=ts,
            event_type="Observed timestamp",
            description=f"Event timestamp observed in {source_name}.",
            source=source_name,
            confidence="Medium",
        ))


def parse_process_records(data: Any, raw_text: str) -> List[ProcessRecord]:
    records = []

    if isinstance(data, dict):
        # Common explicit process lists.
        for key, value in data.items():
            if str(key).lower() in {"processes", "process_tree", "processTree", "process_events"} and isinstance(value, list):
                for item in value[:1000]:
                    if isinstance(item, dict):
                        records.append(ProcessRecord(
                            name=clean(item.get("name") or item.get("process_name") or item.get("image")),
                            pid=clean(item.get("pid")),
                            parent_pid=clean(item.get("parent_pid") or item.get("ppid")),
                            parent_name=clean(item.get("parent_name") or item.get("parent_process")),
                            path=clean(item.get("path") or item.get("exe_path") or item.get("executable")),
                            command_line=sanitize_command_line(clean(item.get("command_line") or item.get("cmdline"))),
                            user=clean(item.get("user") or item.get("username")),
                            start_time=clean(item.get("start_time")),
                            end_time=clean(item.get("end_time")),
                            hash_sha256=clean(item.get("sha256") or item.get("hash")),
                            publisher=clean(item.get("publisher")),
                        ))

    # Fallback to the existing event-level extraction.
    p, cmd = extract_process_info(data, raw_text)
    if p != UNKNOWN and not records:
        records.append(ProcessRecord(name=p, command_line=cmd, user=extract_user_universal(raw_text, data)))

    return records


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_processes(inv: Investigation):
    for p in inv.processes:
        pname = Path(p.name).name.lower() if p.name != UNKNOWN else ""
        cmd = p.command_line.lower() if p.command_line != UNKNOWN else ""
        parent = Path(p.parent_name).name.lower() if p.parent_name != UNKNOWN else ""

        if pname in LOLBINS:
            inv.findings.append(Finding(
                title=f"Living-off-the-land binary observed: {p.name}",
                severity="Medium",
                confidence="Medium",
                evidence_type="DIRECT EVIDENCE",
                description=f"{p.name} is a legitimate Windows utility that is frequently abused by attackers. Its presence alone does not establish malicious activity.",
                evidence_refs=[e.evidence_id for e in inv.evidence],
                implication="Review the command line, parent process, user, destination, and follow-on activity.",
            ))

        if (parent, pname) in SUSPICIOUS_PROCESS_RELATIONSHIPS:
            inv.malicious_indicators.append(
                f"Unusual parent-child process relationship: {parent} -> {pname}."
            )
            inv.findings.append(Finding(
                title="Unusual parent-child process relationship",
                severity="High",
                confidence="High",
                evidence_type="DIRECT EVIDENCE",
                description=f"{parent} spawned {pname}. This is unusual in many environments and warrants investigation.",
                evidence_refs=[e.evidence_id for e in inv.evidence],
                implication="Determine whether the initiating application or document legitimately required the child process.",
            ))

        for label, pattern in SENSITIVE_COMMAND_PATTERNS:
            if pattern.search(cmd):
                inv.malicious_indicators.append(f"Command-line indicator: {label}.")
                severity = "High" if "credential" in label or "encoded" in label else "Medium"
                inv.findings.append(Finding(
                    title=f"Command-line indicator: {label}",
                    severity=severity,
                    confidence="Medium",
                    evidence_type="DIRECT EVIDENCE",
                    description=f"The process command line contains a pattern associated with {label}.",
                    evidence_refs=[e.evidence_id for e in inv.evidence],
                    implication="Validate whether the command was expected and authorized.",
                ))

        if pname in {"powershell.exe", "pwsh.exe"}:
            inv.mitre.append({
                "id": "T1059.001",
                "name": "PowerShell",
                "evidence": p.command_line,
                "confidence": "Medium",
            })

        if any(x in cmd for x in ("schtasks", "new-service", "sc.exe create", "startup")):
            inv.mitre.append({
                "id": "T1053",
                "name": "Scheduled Task/Job or related persistence behavior",
                "evidence": p.command_line,
                "confidence": "Medium",
            })

        if any(x in cmd for x in ("whoami", "ipconfig", "systeminfo", "tasklist", "nltest")):
            inv.mitre.append({
                "id": "T1087/T1016/T1057",
                "name": "Account/System/Process Discovery indicators",
                "evidence": p.command_line,
                "confidence": "Low-Medium",
            })


def analyze_email(inv: Investigation, parsed: Dict[str, Any], evidence_id: str):
    headers = parsed.get("headers", {})
    body = str(parsed.get("body", ""))

    sender = headers.get("From", UNKNOWN)
    recipient = headers.get("To", UNKNOWN)
    subject = headers.get("Subject", UNKNOWN)
    return_path = headers.get("Return-Path", UNKNOWN)
    auth = headers.get("Authentication-Results", UNKNOWN)
    reply_to = headers.get("Reply-To", UNKNOWN)

    inv.actors = unique(inv.actors + [sender])
    inv.domains = unique(inv.domains + extract_domains(
        f"{sender} {recipient} {return_path} {reply_to} {body}"
    ))
    inv.urls = unique(inv.urls + extract_urls(body))

    from_email = parseaddr(sender)[1].lower()
    return_email = parseaddr(return_path)[1].lower()
    if from_email and return_email:
        from_domain = from_email.split("@")[-1]
        return_domain = return_email.split("@")[-1]
        if from_domain != return_domain:
            inv.malicious_indicators.append(
                "From and Return-Path domains do not align."
            )
            inv.findings.append(Finding(
                title="Sender / Return-Path mismatch",
                severity="Medium",
                confidence="High",
                evidence_type="DIRECT EVIDENCE",
                description=f"The visible sender domain ({from_domain}) differs from the Return-Path domain ({return_domain}).",
                evidence_refs=[evidence_id],
                implication="This can occur in legitimate mailing infrastructure, but it is also common in spoofing/phishing.",
            ))

    auth_lower = auth.lower()
    failed = [
        x for x in ("spf=fail", "dkim=fail", "dmarc=fail")
        if x in auth_lower
    ]
    if failed:
        inv.malicious_indicators.append(
            "Email authentication failure: " + ", ".join(failed)
        )
        inv.findings.append(Finding(
            title="Email authentication failure",
            severity="High",
            confidence="High",
            evidence_type="DIRECT EVIDENCE",
            description="Authentication-Results indicates one or more failed email authentication checks.",
            evidence_refs=[evidence_id],
            implication="Validate sender legitimacy, message routing, and whether the failure is expected for the sender's mail infrastructure.",
        ))

    attachments = parsed.get("attachments", [])
    for att in attachments:
        name = clean(att.get("filename"))
        if name != UNKNOWN:
            inv.findings.append(Finding(
                title=f"Email attachment observed: {name}",
                severity="Medium",
                confidence="High",
                evidence_type="DIRECT EVIDENCE",
                description=f"The email contains an attachment named {name}.",
                evidence_refs=[evidence_id],
                implication="Review the attachment type, hash, origin, and whether the recipient expected it.",
            ))


def analyze_html(inv: Investigation, parsed: Dict[str, Any], evidence_id: str):
    urls = parsed.get("urls", [])
    if urls:
        inv.urls = unique(inv.urls + urls)
    if parsed.get("scripts", 0) > 0:
        inv.malicious_indicators.append("HTML contains JavaScript.")
        inv.findings.append(Finding(
            title="HTML contains JavaScript",
            severity="Medium",
            confidence="High",
            evidence_type="DIRECT EVIDENCE",
            description=f"The supplied HTML contains {parsed.get('scripts')} script element(s).",
            evidence_refs=[evidence_id],
            implication="Scripts may be legitimate or may implement redirects, tracking, or malicious behavior. Do not execute the HTML.",
        ))
    if parsed.get("iframes", 0) > 0:
        inv.findings.append(Finding(
            title="HTML contains iframe elements",
            severity="Medium",
            confidence="Medium",
            evidence_type="DIRECT EVIDENCE",
            description=f"The supplied HTML contains {parsed.get('iframes')} iframe element(s).",
            evidence_refs=[evidence_id],
            implication="Review referenced domains and URLs.",
        ))


def analyze_raw_event(inv: Investigation, raw_text: str, data: Any, evidence_id: str, source_name: str):
    process_name, cmd_line = extract_process_info(data, raw_text)
    action = extract_action(data, raw_text, process_name, cmd_line)
    target = extract_target_object(data, raw_text)
    user = extract_user_universal(raw_text, data)
    details = get_event_details(action, cmd_line)

    if user != UNKNOWN:
        inv.actors = unique(inv.actors + [user])
    if target != UNKNOWN:
        inv.assets = unique(inv.assets + [target])

    inv.processes.extend(parse_process_records(data, raw_text))

    inv.findings.append(Finding(
        title=details["title"],
        severity="Medium",
        confidence="Medium",
        evidence_type="DIRECT EVIDENCE",
        description=(
            f"Observed action: {action}. "
            f"Actor: {user}. Process: {process_name}. "
            f"Target: {target}."
        ),
        evidence_refs=[evidence_id],
        implication=details["impact"],
    ))

    if "admin" in user.lower() or "administrator" in user.lower():
        inv.legitimate_indicators.append(
            "The event appears associated with an administrative account; this is context, not proof of benign activity."
        )

    if any(x in raw_text.lower() for x in ("change request", "ticket", "maintenance window", "scheduled maintenance")):
        inv.legitimate_indicators.append(
            "Evidence contains language suggesting an approved operational change or maintenance activity."
        )


# ---------------------------------------------------------------------------
# Source classification and optional remote access
# ---------------------------------------------------------------------------

def classify_url(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if "rapid7" in host or "insightvm" in host or "insightidr" in host:
        return "RAPID7"
    if "security.microsoft.com" in host or "defender" in host:
        return "MICROSOFT_DEFENDER"
    if "crowdstrike" in host or "falcon" in host:
        return "CROWDSTRIKE"
    return "GENERIC_URL"


def url_requires_auth(url: str, provider: str) -> bool:
    # We cannot reliably test arbitrary enterprise portals safely here.
    # Known security portals are treated as authenticated by default.
    return provider in {"RAPID7", "MICROSOFT_DEFENDER", "CROWDSTRIKE"}


def request_provider_credentials(provider: str) -> Optional[str]:
    env_map = {
        "RAPID7": "RAPID7_API_KEY",
        "MICROSOFT_DEFENDER": "DEFENDER_API_TOKEN",
        "CROWDSTRIKE": "CROWDSTRIKE_API_TOKEN",
    }
    env_name = env_map.get(provider)
    if env_name and os.getenv(env_name):
        print(f"Using {env_name} from environment.")
        return os.getenv(env_name)

    print(f"\nAuthenticated access is required for {provider}.")
    print("The credential will NOT be written to the investigation report.")
    try:
        return getpass.getpass("Enter API key/token (blank to continue without API access): ").strip() or None
    except (EOFError, KeyboardInterrupt):
        return None


def extract_rapid7_investigation_id(url: str) -> Optional[str]:
    """Extract the UUID from a Rapid7 InsightIDR investigation URL."""
    m = re.search(
        r"/investigations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        url,
        re.I,
    )
    return m.group(1) if m else None


def rapid7_api_region_from_url(url: str) -> str:
    """Map the InsightIDR web URL region to the API hostname region."""
    host = (urlparse(url).hostname or "").lower()
    for prefix in ("us", "eu", "ca", "au", "ap"):
        if host.startswith(prefix + "."):
            return prefix
    return "us"


def rapid7_get_json(endpoint: str, api_key: str, timeout: int = 30) -> Tuple[bool, Any, str]:
    """Perform a read-only Rapid7 InsightIDR API GET without exposing the key."""
    req = Request(
        endpoint,
        headers={
            "X-Api-Key": api_key,
            "Accept": "application/json",
            "User-Agent": f"SOC-Investigation-Engine/{APP_VERSION}",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            try:
                return True, json.loads(body), f"HTTP {response.status}"
            except json.JSONDecodeError:
                return False, None, "Rapid7 returned a non-JSON response."
    except HTTPError as exc:
        if exc.code == 401:
            return False, None, "Rapid7 API authentication failed (HTTP 401)."
        if exc.code == 403:
            return False, None, "Rapid7 API access denied (HTTP 403). Check API-key permissions."
        if exc.code == 404:
            return False, None, "Rapid7 investigation was not found (HTTP 404)."
        return False, None, f"Rapid7 API returned HTTP {exc.code}."
    except URLError as exc:
        return False, None, f"Unable to reach Rapid7 API: {exc.reason}"
    except TimeoutError:
        return False, None, "Rapid7 API request timed out."
    except Exception as exc:
        LOGGER.exception("Rapid7 API request failed")
        return False, None, f"Rapid7 API request failed: {type(exc).__name__}"


def fetch_authenticated_url(url: str, provider: str, credential: Optional[str]) -> Tuple[bool, str, str]:
    """
    Read-only Rapid7 InsightIDR v2 integration.

    Retrieves:
      1. Investigation details
      2. Alerts associated with the investigation
      3. Rapid7 product alerts associated with the investigation

    No investigation update, assignment, disposition, or closure operation
    is performed automatically.
    """
    if not credential:
        return False, "", "No credential supplied."

    if provider != "RAPID7":
        return False, "", (
            f"{provider} URL detected, but no authenticated connector is enabled "
            "for that provider in this version."
        )

    investigation_id = extract_rapid7_investigation_id(url)
    if not investigation_id:
        return False, "", "Could not extract a Rapid7 investigation UUID from the supplied URL."

    region = rapid7_api_region_from_url(url)
    base = f"https://{region}.api.insight.rapid7.com/idr/v2/investigations"

    ok, investigation, status = rapid7_get_json(
        f"{base}/{investigation_id}", credential
    )
    if not ok:
        return False, "", status

    ok_alerts, alerts, alert_status = rapid7_get_json(
        f"{base}/{investigation_id}/alerts?index=0&size=100",
        credential,
    )
    if not ok_alerts:
        alerts = {"error": alert_status}

    ok_products, products, product_status = rapid7_get_json(
        f"{base}/{investigation_id}/rapid7-product-alerts",
        credential,
    )
    if not ok_products:
        products = {"error": product_status}

    payload = {
        "rapid7_integration": {
            "provider": "Rapid7 InsightIDR",
            "region": region,
            "investigation_id": investigation_id,
            "source_url": url,
            "read_only": True,
            "investigation_retrieved": True,
            "alerts_retrieved": ok_alerts,
            "product_alerts_retrieved": ok_products,
        },
        "investigation": investigation,
        "associated_alerts": alerts,
        "rapid7_product_alerts": products,
    }

    return True, json.dumps(payload, ensure_ascii=False), (
        f"Rapid7 investigation {investigation_id} retrieved successfully "
        f"({status}); associated alerts: {'OK' if ok_alerts else 'unavailable'}; "
        f"product alerts: {'OK' if ok_products else 'unavailable'}."
    )


# ---------------------------------------------------------------------------
# Verdict / risk engine
# ---------------------------------------------------------------------------

def assess_verdict(inv: Investigation):
    high_findings = sum(1 for f in inv.findings if f.severity == "High")
    medium_findings = sum(1 for f in inv.findings if f.severity == "Medium")

    # Positive evidence for legitimate activity.
    legit = len(inv.legitimate_indicators)
    malicious = len(inv.malicious_indicators)

    # Explicit user/analyst confirmations are stronger than generic context.
    user_verified = any(
        "user confirmed" in x.lower() or "verified by user" in x.lower()
        for x in inv.analyst_notes
    )
    approved_change = any(
        any(term in x.lower() for term in ("approved change", "change ticket", "maintenance window", "scheduled maintenance"))
        for x in inv.legitimate_indicators
    )

    if user_verified and approved_change and malicious == 0:
        inv.verdict = "FALSE POSITIVE"
        inv.confidence = "High"
        inv.verdict_reason = (
            "The available evidence includes explicit validation and an approved operational explanation, "
            "with no identified malicious follow-on behavior."
        )
    elif high_findings >= 2 and malicious >= 2:
        inv.verdict = "TRUE POSITIVE"
        inv.confidence = "High"
        inv.verdict_reason = (
            "Multiple independent indicators support malicious or unauthorized behavior, "
            "including high-severity process/command or authentication evidence."
        )
    elif malicious >= 2 and high_findings >= 1:
        inv.verdict = "SUSPICIOUS / REQUIRES INVESTIGATION"
        inv.confidence = "High"
        inv.verdict_reason = (
            "The evidence contains multiple suspicious indicators, but the available data does not yet prove "
            "malicious intent or complete impact."
        )
    elif malicious >= 1:
        inv.verdict = "SUSPICIOUS / REQUIRES INVESTIGATION"
        inv.confidence = "Medium"
        inv.verdict_reason = (
            "At least one meaningful suspicious indicator was identified. Additional contextual validation is required."
        )
    elif legit >= 2:
        inv.verdict = "BENIGN / EXPECTED ACTIVITY"
        inv.confidence = "Medium"
        inv.verdict_reason = (
            "The available evidence contains multiple indicators consistent with legitimate operational activity, "
            "but a benign assessment should be confirmed against organizational context."
        )
    else:
        inv.verdict = "INCONCLUSIVE"
        inv.confidence = "Low"
        inv.verdict_reason = (
            "The supplied evidence is insufficient to establish either malicious or clearly legitimate activity."
        )

    if inv.verdict in {"TRUE POSITIVE", "SUSPICIOUS / REQUIRES INVESTIGATION"}:
        inv.recommended_severity = "High" if high_findings >= 2 else "Medium"
    elif inv.verdict == "INCONCLUSIVE":
        inv.recommended_severity = "Medium"
    else:
        inv.recommended_severity = "Low"

    # Assignment based on evidence category.
    all_text = " ".join(inv.malicious_indicators + [f.description for f in inv.findings]).lower()
    if any(x in all_text for x in ("process", "powershell", "endpoint", "cmd.exe", "malware")):
        inv.recommended_owner = "Endpoint / EDR Team"
    if any(x in all_text for x in ("email", "sender", "spf", "dkim", "dmarc", "phishing")):
        inv.recommended_owner = "Email Security / SOC"
    if any(x in all_text for x in ("privileged", "group", "credential", "authentication")):
        inv.recommended_owner = "IAM / SOC"
    if not inv.findings:
        inv.recommended_owner = "SOC / SecOps"


def generate_questions(inv: Investigation):
    inv.user_questions.clear()
    inv.it_questions.clear()

    process_text = " ".join(p.command_line for p in inv.processes).lower()

    if inv.actors:
        inv.user_questions.append({
            "question": f"Did you personally perform or authorize the activity associated with {inv.actors[0]}?",
            "why": "User confirmation can distinguish expected activity from potentially unauthorized use of the account.",
        })

    if any("powershell" in p.name.lower() for p in inv.processes):
        inv.user_questions.append({
            "question": "Did you intentionally launch PowerShell or run a PowerShell-based tool at the reported time?",
            "why": "PowerShell can be legitimate administration but is also frequently abused for execution.",
        })

    if "download" in process_text or inv.urls:
        inv.user_questions.append({
            "question": "Did you intentionally download or access the referenced URL/file?",
            "why": "This helps determine whether the network or file activity was user-initiated.",
        })

    if inv.malicious_indicators:
        inv.user_questions.append({
            "question": "Do you recognize the process, file, command, or email involved in this alert?",
            "why": "Recognition or denial provides important context for determining whether the activity was expected.",
        })

    inv.it_questions.extend([
        {
            "question": "Was there an approved change, deployment, maintenance task, or troubleshooting activity corresponding to this event?",
            "why": "A matching operational record is strong contextual evidence for legitimate activity.",
        },
        {
            "question": "Was the affected device/account expected to perform this action?",
            "why": "Role and asset ownership help determine whether the behavior fits the environment.",
        },
    ])

    if any("group" in f.title.lower() or "privileg" in f.title.lower() for f in inv.findings):
        inv.it_questions.append({
            "question": "Was the privilege or group membership change approved through the normal access-management process?",
            "why": "Unauthorized privilege changes can indicate persistence or privilege escalation.",
        })


def identify_missing_information(inv: Investigation):
    missing = []

    if not inv.actors:
        missing.append("Actor/user identity was not reliably identified.")
    if not inv.assets:
        missing.append("Affected asset/hostname was not reliably identified.")
    if not inv.timeline:
        missing.append("A reliable event timestamp/timeline was not available.")
    if not inv.processes:
        missing.append("Process/process-tree evidence was not available.")
    if not inv.urls and not inv.ips:
        missing.append("No network destination evidence was available.")
    if inv.verdict in {"INCONCLUSIVE", "SUSPICIOUS / REQUIRES INVESTIGATION"}:
        missing.append("User or system-owner validation may be required before closure.")

    inv.missing_information = unique(missing, 100)


def generate_remediation(inv: Investigation):
    inv.remediation.clear()

    if inv.verdict == "TRUE POSITIVE":
        inv.remediation.extend([
            "Contain the affected endpoint/account according to the organization's incident-response procedure.",
            "Preserve relevant evidence before destructive remediation where practical.",
            "Validate credential exposure and reset/revoke affected credentials if compromise is suspected.",
            "Review related alerts and activity for lateral movement, persistence, or additional affected assets.",
            "Document containment and remediation actions in the incident record.",
        ])
    elif inv.verdict == "SUSPICIOUS / REQUIRES INVESTIGATION":
        inv.remediation.extend([
            "Obtain user/system-owner validation before closing the investigation.",
            "Correlate the alert with nearby authentication, process, network, and endpoint events.",
            "Escalate to Incident Response if additional malicious indicators are confirmed.",
        ])
    elif inv.verdict == "FALSE POSITIVE":
        inv.remediation.extend([
            "Document the legitimate business/technical reason for the activity.",
            "Consider detection tuning only if the behavior is repeatedly confirmed as legitimate.",
        ])
    else:
        inv.remediation.append(
            "Collect the missing evidence identified in this report before making a definitive disposition."
        )


def generate_closure(inv: Investigation) -> str:
    source = ", ".join(inv.raw_sources) if inv.raw_sources else UNKNOWN
    evidence_summary = "; ".join(
        f.description for f in inv.findings[:5]
    ) or "No material findings were generated."

    if inv.verdict == "FALSE POSITIVE":
        action = (
            "The alert is being closed as False Positive based on the available evidence and documented "
            "legitimate context. No malicious follow-on activity was identified in the supplied evidence."
        )
    elif inv.verdict == "BENIGN / EXPECTED ACTIVITY":
        action = (
            "The activity appears consistent with expected administrative or business activity. "
            "The evidence does not currently indicate malicious behavior."
        )
    elif inv.verdict == "TRUE POSITIVE":
        action = (
            "The activity is assessed as a True Positive based on multiple supporting indicators. "
            "Containment, remediation, and related-activity review are recommended."
        )
    elif inv.verdict == "SUSPICIOUS / REQUIRES INVESTIGATION":
        action = (
            "The alert remains suspicious and requires additional validation before closure. "
            "The evidence is not sufficient to state malicious intent conclusively."
        )
    else:
        action = (
            "The investigation is inconclusive because the available evidence does not establish a definitive "
            "benign or malicious explanation."
        )

    return (
        f"Investigation {inv.investigation_id} reviewed. "
        f"Source: {source}. "
        f"Final disposition: {inv.verdict} (confidence: {inv.confidence}). "
        f"{inv.verdict_reason} "
        f"Key findings: {evidence_summary} "
        f"Recommended owner: {inv.recommended_owner}. "
        f"{action}"
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def plain_english_summary(inv: Investigation) -> str:
    actor = ", ".join(inv.actors[:5]) if inv.actors else UNKNOWN
    asset = ", ".join(inv.assets[:5]) if inv.assets else UNKNOWN

    if inv.processes:
        proc = inv.processes[0]
        process_sentence = (
            f"The main process evidence shows {proc.name}, "
            f"with command line: {proc.command_line}."
        )
    else:
        process_sentence = "No reliable process information was available."

    return (
        f"The investigation reviewed alert evidence involving {actor} on {asset}. "
        f"{process_sentence} "
        f"The analysis identified {len(inv.findings)} finding(s), "
        f"{len(inv.malicious_indicators)} suspicious indicator(s), and "
        f"{len(inv.legitimate_indicators)} legitimate-context indicator(s). "
        f"The current assessment is {inv.verdict} with {inv.confidence} confidence. "
        f"{inv.verdict_reason}"
    )


def render_report(inv: Investigation) -> str:
    lines = []
    add = lines.append

    add("=" * 78)
    add(f"{APP_NAME} v{APP_VERSION}")
    add("=" * 78)
    add(f"Investigation ID : {inv.investigation_id}")
    add(f"Created          : {inv.created_at}")
    add(f"Analyst          : {inv.analyst}")
    add(f"Alert ID         : {inv.alert_id}")
    add(f"Detection Source : {inv.detection_source}")
    add(f"Alert Name       : {inv.alert_name}")
    add(f"Severity         : {inv.severity}")
    add("")

    add("1. EXECUTIVE SUMMARY")
    add("-" * 78)
    add(textwrap.fill(plain_english_summary(inv), 110))
    add("")

    add("2. WHAT HAPPENED")
    add("-" * 78)
    add(textwrap.fill(
        " ".join(
            f"- {f.description}" for f in inv.findings[:10]
        ) or "No material event description could be established from the supplied evidence.",
        110,
    ))
    add("")

    add("3. ACTOR / USER")
    add("-" * 78)
    add(", ".join(inv.actors) if inv.actors else UNKNOWN)
    add("")

    add("4. ASSET / DEVICE")
    add("-" * 78)
    add(", ".join(inv.assets) if inv.assets else UNKNOWN)
    add("")

    add("5. NETWORK INDICATORS")
    add("-" * 78)
    add(f"IPs     : {', '.join(inv.ips) if inv.ips else UNKNOWN}")
    add(f"Domains : {', '.join(inv.domains) if inv.domains else UNKNOWN}")
    add(f"URLs    : {', '.join(inv.urls) if inv.urls else UNKNOWN}")
    add(f"Hashes  : {', '.join(inv.hashes) if inv.hashes else UNKNOWN}")
    add("")

    add("6. PROCESS ANALYSIS")
    add("-" * 78)
    if inv.processes:
        for p in inv.processes[:100]:
            add(f"Process       : {p.name}")
            add(f"PID           : {p.pid}")
            add(f"Parent PID    : {p.parent_pid}")
            add(f"Parent        : {p.parent_name}")
            add(f"Path          : {p.path}")
            add(f"Command       : {p.command_line}")
            add(f"User          : {p.user}")
            add(f"SHA256        : {p.hash_sha256}")
            add("")
    else:
        add(UNKNOWN)
    add("")

    add("7. TIMELINE")
    add("-" * 78)
    if inv.timeline:
        for e in sorted(inv.timeline, key=lambda x: x.timestamp)[:500]:
            add(f"{e.timestamp} | {e.event_type} | {e.description} | {e.source}")
    else:
        add(UNKNOWN)
    add("")

    add("8. FINDINGS")
    add("-" * 78)
    if inv.findings:
        for i, f in enumerate(inv.findings, 1):
            add(f"[{i}] {f.title}")
            add(f"Severity   : {f.severity}")
            add(f"Confidence : {f.confidence}")
            add(f"Evidence   : {f.evidence_type}")
            add(f"Description: {f.description}")
            if f.implication:
                add(f"Implication: {f.implication}")
            add("")
    else:
        add("No findings.")
    add("")

    add("9. LEGITIMATE ACTIVITY INDICATORS")
    add("-" * 78)
    for x in inv.legitimate_indicators or [UNKNOWN]:
        add(f"- {x}")
    add("")

    add("10. MALICIOUS / SUSPICIOUS INDICATORS")
    add("-" * 78)
    for x in inv.malicious_indicators or [UNKNOWN]:
        add(f"- {x}")
    add("")

    add("11. MISSING INFORMATION")
    add("-" * 78)
    for x in inv.missing_information or [UNKNOWN]:
        add(f"- {x}")
    add("")

    add("12. USER QUESTIONS")
    add("-" * 78)
    for q in inv.user_questions or [{"question": UNKNOWN, "why": UNKNOWN}]:
        add(f"Question: {q['question']}")
        add(f"Why     : {q['why']}")
    add("")

    add("13. IT / SYSTEM OWNER QUESTIONS")
    add("-" * 78)
    for q in inv.it_questions or [{"question": UNKNOWN, "why": UNKNOWN}]:
        add(f"Question: {q['question']}")
        add(f"Why     : {q['why']}")
    add("")

    add("14. MITRE ATT&CK")
    add("-" * 78)
    if inv.mitre:
        for m in inv.mitre:
            add(f"{m['id']} | {m['name']} | {m['confidence']} | {m['evidence']}")
    else:
        add(UNKNOWN)
    add("")

    add("15. FINAL VERDICT")
    add("-" * 78)
    add(f"Verdict             : {inv.verdict}")
    add(f"Confidence          : {inv.confidence}")
    add(f"Recommended Severity: {inv.recommended_severity}")
    add(f"Recommended Owner   : {inv.recommended_owner}")
    add(f"Reason              : {inv.verdict_reason}")
    add("")

    add("16. RECOMMENDED REMEDIATION")
    add("-" * 78)
    for x in inv.remediation or [UNKNOWN]:
        add(f"- {x}")
    add("")

    add("17. CLOSURE COMMENTS")
    add("-" * 78)
    add(textwrap.fill(inv.closure_comments or UNKNOWN, 110))
    add("")

    add("18. EVIDENCE REGISTER")
    add("-" * 78)
    for e in inv.evidence:
        add(f"{e.evidence_id} | {e.source_type} | {e.source_name}")
        add(f"  Status: {e.status}")
        add(f"  SHA256: {e.content_hash_sha256 or UNKNOWN}")
        add(f"  Notes : {e.notes}")
    add("")

    add("19. ANALYST NOTES")
    add("-" * 78)
    for n in inv.analyst_notes or [UNKNOWN]:
        add(f"- {redact_secret(n)}")
    add("")

    add("=" * 78)
    add("END OF INVESTIGATION REPORT")
    add("=" * 78)

    return "\n".join(lines)


def write_outputs(inv: Investigation) -> Tuple[Path, Path]:
    folder = REPORT_DIR / inv.investigation_id
    folder.mkdir(parents=True, exist_ok=True)

    txt_path = folder / "investigation_report.txt"
    json_path = folder / "investigation_report.json"

    txt_path.write_text(render_report(inv), encoding="utf-8")

    payload = asdict(inv)
    # Defense in depth: never serialize secret-like fields.
    payload.pop("api_key", None)
    payload.pop("token", None)
    payload.pop("credential", None)

    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return txt_path, json_path


# ---------------------------------------------------------------------------
# Investigation workflow
# ---------------------------------------------------------------------------

def process_local_file(inv: Investigation, path_str: str):
    path = Path(path_str.strip().strip('"').strip("'"))
    if not path.exists() or not path.is_file():
        print(f"ERROR: File not found: {path}")
        return

    try:
        file_hash = sha256_file(path)
        source_type, raw, parsed = parse_file(path)
        eid = add_evidence(
            inv,
            source_type,
            str(path),
            f"Local evidence file {path.name}",
            content_hash=file_hash,
            notes="Processed locally; no API credentials required.",
        )
        inv.raw_sources.append(str(path))

        print(f"✓ Loaded {source_type}: {path.name}")
        print("✓ SHA256 calculated")
        print("✓ No API access required")

        if source_type in {"EMAIL", "MSG"}:
            analyze_email(inv, parsed, eid)
        elif source_type == "HTML":
            analyze_html(inv, parsed, eid)
            analyze_raw_event(inv, raw, parsed, eid, path.name)
        else:
            analyze_raw_event(inv, raw, parsed, eid, path.name)

        collect_common_indicators(inv, raw, parsed)
        collect_timestamps(inv, parsed, path.name)

    except Exception as exc:
        LOGGER.exception("Failed processing file %s", path)
        add_evidence(
            inv, "ERROR", str(path),
            "Evidence could not be fully processed.",
            status="error",
            notes=str(exc),
        )
        print(f"ERROR processing {path}: {exc}")


def process_raw_text(inv: Investigation, raw_text: str):
    eid = add_evidence(
        inv, "RAW_TEXT", "Analyst pasted event",
        "Raw event supplied directly by analyst.",
        content_hash=sha256_bytes(raw_text.encode("utf-8")),
        notes="Processed locally; no API credentials required.",
    )
    inv.raw_sources.append("Analyst pasted event")
    data = safe_json_loads(raw_text)
    analyze_raw_event(inv, raw_text, data, eid, "Pasted event")
    collect_common_indicators(inv, raw_text, data)
    collect_timestamps(inv, data, "Pasted event")


def process_url(inv: Investigation, url: str):
    provider = classify_url(url)
    inv.raw_sources.append(url)
    print(f"\nDetected source: {provider}")

    if url_requires_auth(url, provider):
        credential = request_provider_credentials(provider)
        ok, content, note = fetch_authenticated_url(url, provider, credential)
        if ok and content:
            parsed_remote = safe_json_loads(content)
            eid = add_evidence(
                inv, provider, url,
                f"Authenticated read-only data retrieved from {provider}.",
                content_hash=sha256_bytes(content.encode()),
                notes="Retrieved using authenticated provider integration. API credential is not stored.",
            )
            inv.raw_events.append(
                parsed_remote if isinstance(parsed_remote, dict) else {"raw": content}
            )
            analyze_raw_event(inv, content, parsed_remote, eid, url)
            collect_common_indicators(inv, content, parsed_remote)
            collect_timestamps(inv, parsed_remote, url)

            if isinstance(parsed_remote, dict):
                r7 = parsed_remote.get("investigation", {})
                if isinstance(r7, dict):
                    meta = parsed_remote.get("rapid7_integration", {})
                    inv.alert_id = clean(
                        r7.get("id") or r7.get("investigation_id") or meta.get("investigation_id"),
                        inv.alert_id,
                    )
                    inv.alert_name = clean(r7.get("title") or r7.get("name"), inv.alert_name)
                    inv.severity = clean(r7.get("priority"), inv.severity)
                    inv.detection_source = "Rapid7 InsightIDR"
                    if r7.get("assignee"):
                        inv.recommended_owner = clean(r7.get("assignee"), inv.recommended_owner)
                    if r7.get("status"):
                        inv.analyst_notes.append(
                            f"Rapid7 investigation status at retrieval: {clean(r7.get('status'))}."
                        )
                    if r7.get("disposition"):
                        inv.analyst_notes.append(
                            f"Rapid7 disposition at retrieval: {clean(r7.get('disposition'))}."
                        )
        else:
            eid = add_evidence(
                inv, provider, url,
                f"Remote URL could not be retrieved through the configured integration.",
                status="not_retrieved",
                notes=note,
            )
            print(f"⚠ {note}")
            print("Continue by supplying exported JSON/HTML/EML/log evidence.")
    else:
        # Do not blindly download arbitrary URLs. The engine records the URL and
        # asks the analyst to provide exported content unless a safe connector
        # is explicitly implemented.
        eid = add_evidence(
            inv, provider, url,
            "URL supplied for investigation; remote content was not automatically executed or trusted.",
            status="reference_only",
            notes="Provide exported evidence or configure an authorized connector.",
        )
        print("✓ URL recorded as evidence reference.")
        print("✓ No API key requested.")


def run_analysis(inv: Investigation):
    print("\nAnalyzing evidence...")
    inv.processes = dedupe_processes(inv.processes)
    analyze_processes(inv)
    generate_questions(inv)
    identify_missing_information(inv)
    assess_verdict(inv)
    generate_remediation(inv)
    inv.closure_comments = generate_closure(inv)
    print("✓ Evidence normalized")
    print("✓ Process analysis completed")
    print("✓ Behavioral analysis completed")
    print("✓ Verdict assessment completed")
    print("✓ Questions generated")
    print("✓ Closure comments generated")


def dedupe_processes(processes: List[ProcessRecord]) -> List[ProcessRecord]:
    out = []
    seen = set()
    for p in processes:
        key = (p.name, p.pid, p.parent_pid, p.command_line)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out[:1000]


def ask_metadata(inv: Investigation):
    print("\nOptional investigation metadata. Press ENTER to leave a field unknown.")
    inv.analyst = input("Analyst name: ").strip() or UNKNOWN
    inv.alert_id = input("Alert / Incident ID: ").strip() or UNKNOWN
    inv.alert_name = input("Alert name: ").strip() or UNKNOWN
    inv.severity = input("Original alert severity: ").strip() or UNKNOWN
    inv.detection_source = input("Detection source/product: ").strip() or UNKNOWN


def interactive():
    print("=" * 78)
    print(f"{APP_NAME} v{APP_VERSION}")
    print("=" * 78)
    print("Evidence-first SOC investigation assistant.")
    print("Local JSON/LOG/EML/MSG/HTML files do NOT require API keys.")
    print("API credentials are requested only for authenticated provider access.")
    print()

    inv = Investigation(
        investigation_id=investigation_id(),
        created_at=now_iso(),
    )
    ask_metadata(inv)

    while True:
        print("\n" + "-" * 78)
        print("ADD INVESTIGATION EVIDENCE")
        print("-" * 78)
        print("1. Local JSON / TXT / LOG / XML / CSV")
        print("2. EML email")
        print("3. MSG email")
        print("4. HTML")
        print("5. Security-platform / Rapid7 / Defender URL")
        print("6. Paste raw event/log")
        print("7. Finish evidence collection")
        print("8. Exit without report")

        choice = input("\nSelect: ").strip()

        if choice == "1":
            process_local_file(inv, input("Enter file path: "))
        elif choice == "2":
            process_local_file(inv, input("Enter EML file path: "))
        elif choice == "3":
            process_local_file(inv, input("Enter MSG file path: "))
        elif choice == "4":
            process_local_file(inv, input("Enter HTML file path: "))
        elif choice == "5":
            process_url(inv, input("Enter investigation URL: ").strip())
        elif choice == "6":
            print("Paste the raw event. Enter a line containing END-OF-EVIDENCE when finished.")
            chunks = []
            while True:
                line = input()
                if line.strip() == "END-OF-EVIDENCE":
                    break
                chunks.append(line)
            process_raw_text(inv, "\n".join(chunks))
        elif choice == "7":
            break
        elif choice == "8":
            print("Exiting without generating a report.")
            return
        else:
            print("Invalid selection.")

    if not inv.evidence:
        print("No evidence supplied. Nothing to investigate.")
        return

    print("\nAdd an analyst note? Leave blank to skip.")
    note = input("Note: ").strip()
    if note:
        inv.analyst_notes.append(redact_secret(note))

    run_analysis(inv)

    txt_path, json_path = write_outputs(inv)

    print("\n" + "=" * 78)
    print("INVESTIGATION COMPLETE")
    print("=" * 78)
    print(f"Investigation : {inv.investigation_id}")
    print(f"Verdict       : {inv.verdict}")
    print(f"Confidence    : {inv.confidence}")
    print(f"Severity      : {inv.recommended_severity}")
    print(f"Owner         : {inv.recommended_owner}")
    print()
    print("Plain-English conclusion:")
    print(textwrap.fill(plain_english_summary(inv), 110))
    print()
    print(f"TXT report    : {txt_path}")
    print(f"JSON report   : {json_path}")
    print("=" * 78)


def cli_file(path: str):
    inv = Investigation(
        investigation_id=investigation_id(),
        created_at=now_iso(),
        analyst=os.getenv("USERNAME") or os.getenv("USER") or UNKNOWN,
    )
    process_local_file(inv, path)
    if not inv.evidence:
        return 1
    run_analysis(inv)
    txt, js = write_outputs(inv)
    print(render_report(inv))
    print(f"\nSaved: {txt}")
    print(f"Saved: {js}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument(
        "--file",
        help="Analyze a local evidence file directly without the interactive menu.",
    )
    args = parser.parse_args()

    try:
        if args.file:
            return cli_file(args.file)
        interactive()
        return 0
    except KeyboardInterrupt:
        print("\nExiting.")
        return 130
    except Exception as exc:
        LOGGER.exception("Fatal error")
        print(f"\nFatal error: {exc}")
        if os.getenv("SOC_DEBUG") == "1":
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
