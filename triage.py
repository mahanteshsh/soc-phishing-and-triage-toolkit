from email import policy
from email.parser import HeaderParser
import html.parser
import json
import os
import re
import xml.etree.ElementTree as ET

# 1. 📚 SIEM Translation Dictionary
EVENT_DICTIONARY = {
    "powershell": {
        "title": "PowerShell Script / Remote Command Execution ⚡",
        "example": (
            "(like executing an automated script to download files or run"
            " administrative tasks)"
        ),
        "why_fp": (
            "An engineer or system admin running deployment scripts,"
            " infrastructure maintenance, or automated management tools."
        ),
        "why_tp": (
            "An attacker or malware using built-in Windows tools to download"
            " secondary payloads or execute malicious scripts."
        ),
        "impact": (
            "Can download external files, modify local system settings, or"
            " execute arbitrary code with the user's privileges."
        ),
    },
    "member_added_to_security_group": {
        "title": "User Added to Security / Privileged Group 🛡️",
        "example": (
            "(like giving an employee an 'Administrator' badge to access"
            " restricted server rooms)"
        ),
        "why_fp": (
            "An IT Admin legitimately adding a team member to a role-based"
            " access group during onboarding."
        ),
        "why_tp": (
            "An attacker escalating privileges to gain unauthorized access to"
            " domain controllers or sensitive resources."
        ),
        "impact": (
            "Grants target user new access permissions or administrative"
            " rights."
        ),
    },
    "createservicespecificcredential": {
        "title": "Created Git / Code Access Passwords 🔑",
        "example": (
            "(like generating an access token to download or upload source"
            " code)"
        ),
        "why_fp": (
            "A developer legitimately generating credentials to access a"
            " repository."
        ),
        "why_tp": (
            "An attacker generating credentials to secretly exfiltrate"
            " proprietary source code."
        ),
        "impact": (
            "Provides persistent direct access to internal code repositories."
        ),
    },
    "cmdkey.exe": {
        "title": "Inspected Saved Windows Passwords 🔐",
        "example": (
            "(like opening Windows password manager to view saved network"
            " passwords)"
        ),
        "why_fp": (
            "A system administrator troubleshooting network connectivity or"
            " automated account access."
        ),
        "why_tp": (
            "An attacker harvesting saved credentials for lateral movement"
            " across the network."
        ),
        "impact": (
            "Exposes saved domain credentials to potential privilege"
            " escalation."
        ),
    },
}


# 2. 📧 Email Header Parser Engine
def is_email_header(raw_content):
  """Detect if file content represents an email or email header."""
  keywords = [
      "Received:",
      "From:",
      "Subject:",
      "Return-Path:",
      "Authentication-Results:",
      "Delivered-To:",
  ]
  match_count = sum(1 for kw in keywords if kw.lower() in raw_content.lower())
  return match_count >= 2


def print_email_report(raw_content):
  """Parses email headers and outputs plain-English phishing/spoofing triage report."""
  parser = HeaderParser(policy=policy.default)
  headers = parser.parsestr(raw_content)

  subject = headers.get("Subject", "N/A")
  from_header = headers.get("From", "N/A")
  to_header = headers.get("To", "N/A")
  return_path = headers.get("Return-Path", "N/A")
  auth_results = headers.get("Authentication-Results", "N/A")

  received_list = headers.get_all("Received") or []
  originating_ip = "N/A"
  for r in reversed(received_list):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(r))
    if ip_match and not ip_match.group(0).startswith("127."):
      originating_ip = ip_match.group(0)
      break

  from_email_match = re.search(r"[\w\.-]+@[\w\.-]+", str(from_header))
  from_email = (
      from_email_match.group(0) if from_email_match else str(from_header)
  )
  return_path_clean = str(return_path).strip("<> ")
  is_mismatched = (return_path_clean != "N/A") and (
      return_path_clean.split("@")[-1].lower() not in from_email.lower()
  )

  auth_str = str(auth_results).lower()
  has_auth_fail = (
      "spf=fail" in auth_str or "dkim=fail" in auth_str or "dmarc=fail" in auth_str
  )

  print(
      "\n================ 🛡️ EMAIL HEADER TRIAGE REPORT 🛡️ ================"
  )
  print(f"SENDER / FROM     : {from_header}")
  print(f"RECIPIENT / TO    : {to_header}")
  print(f"SUBJECT           : {subject}")
  print(f"RETURN-PATH       : {return_path}")
  print(f"ORIGINATING IP    : {originating_ip}")
  print(f"AUTH RESULTS      : {auth_results}")
  print("-----------------------------------------------------------------")

  print("\n📜 WHAT HAPPENED:")
  print(
      f"• Analyzed email header from '{from_header}' to"
      f" '{to_header}'."
  )
  print(f"• Subject: '{subject}'")
  print(f"• Originating Server IP: {originating_ip}")

  print("\n💡 ANALYSIS & CONTEXT:")
  if is_mismatched:
    print(
        "🔴 SENDER MISMATCH DETECTED: 'From' domain does not match"
        " 'Return-Path' domain."
    )
  if has_auth_fail:
    print(
        "🔴 AUTHENTICATION FAILURE DETECTED: SPF, DKIM, or DMARC validation"
        " failed."
    )
  if not is_mismatched and not has_auth_fail:
    print(
        "🟢 HEADER CHECKS PASSED: Sender alignment and domain authentication"
        " appeared valid."
    )

  print("\n🏷️ CLASSIFICATION:")
  if is_mismatched or has_auth_fail:
    print("   [SUSPICIOUS / POTENTIAL PHISHING OR SPOOFING]")
  else:
    print("   [BENIGN / INFORMATIONAL HEADER]")

  print("\n🎯 RECOMMENDED ACTION:")
  if is_mismatched or has_auth_fail:
    print(
        f"   ACTION REQUIRED: Investigate sender IP ({originating_ip}) and block"
        " unverified domain."
    )
  else:
    print(
        "   INFORMATIONAL: Header structure is valid. No domain spoofing"
        " detected."
    )
  print("=================================================================\n")


# 3. 🔍 Universal SIEM/JSON Log Extractors
def extract_user_universal(raw_text, data_dict=None):
  user_candidates = []
  if isinstance(data_dict, dict):
    keys_to_check = [
        "user",
        "source_user",
        "sourceUser",
        "userName",
        "username",
        "account",
        "SubjectUserName",
        "TargetUserName",
        "AccountName",
        "caller",
        "actor",
        "target_user",
        "target_member",
        "target_account",
    ]

    def search_dict(d):
      if not isinstance(d, dict):
        return
      for k, v in d.items():
        if any(k.lower() == x.lower() for x in keys_to_check):
          if (
              isinstance(v, str)
              and v.strip()
              and v.strip().lower() not in ["n/a", "unknown", "null", "none"]
          ):
            user_candidates.append(v.strip())
          elif isinstance(v, dict):
            for name_k in [
                "name",
                "username",
                "alternateIdentifier",
                "value",
                "id",
            ]:
              if v.get(name_k) and isinstance(v.get(name_k), str):
                user_candidates.append(str(v.get(name_k)).strip())
        elif isinstance(v, dict):
          search_dict(v)
        elif isinstance(v, list):
          for item in v:
            if isinstance(item, dict):
              search_dict(item)

    search_dict(data_dict)

  if "<" in raw_text and ">" in raw_text:
    try:
      xml_matches = re.findall(
          r'<Data\s+Name=["\'](?:SubjectUserName|TargetUserName|User|AccountName|SourceUser|TargetUser)["\']>\s*([^<]+)\s*</Data>',
          raw_text,
          re.IGNORECASE,
      )
      for m in xml_matches:
        if m.strip() and m.strip().lower() not in ["n/a", "-", "unknown"]:
          user_candidates.append(m.strip())
    except Exception:
      pass

  path_matches = re.findall(
      r"[Cc]:[\\/]Users[\\/]([^\\/\r\n\"'\s;,]+)", raw_text
  )
  for pm in path_matches:
    if pm.lower() not in [
        "public",
        "default",
        "default user",
        "all users",
        "desktop.ini",
    ]:
      user_candidates.append(pm.strip())

  clean_text = re.sub(r"<[^>]+>", " ", raw_text)
  text_matches = re.findall(
      r"(?:source_?user|target_?user|subject_?username|target_?username|account\s*name|user\s*account|user\s*name|actor|caller|user)[\s:=]+([A-Za-z0-9._\\@\s-]+?)(?=\s{2,}|\b(?:Path|Executed|Event|Process|Command|Target)\b|[,\"\';\r\n|]|$)",
      clean_text,
      re.IGNORECASE,
  )
  for tm in text_matches:
    val = tm.strip()
    if val and val.lower() not in [
        "n/a",
        "unknown",
        "null",
        "none",
        "is",
        "the",
        "a",
        "executed",
    ]:
      user_candidates.append(val)

  valid_candidates = [
      u
      for u in user_candidates
      if u and u.lower() not in ["n/a", "unknown", "null", "none", "-"]
  ]
  for u in valid_candidates:
    if (
        "system" not in u.lower()
        and "local service" not in u.lower()
        and "network service" not in u.lower()
    ):
      return u
  return valid_candidates[0] if valid_candidates else "Unknown User"


def extract_process_info(data, raw_text):
  p_name, cmd = "N/A", "N/A"
  if isinstance(data, dict):
    proc_obj = data.get("process")
    if isinstance(proc_obj, dict):
      p_name = proc_obj.get("name") or proc_obj.get("exe_path") or "N/A"
      cmd = proc_obj.get("cmd_line") or proc_obj.get("cmdline") or "N/A"
      return p_name, cmd
    p_name = (
        data.get("process_name")
        or data.get("exe")
        or (str(proc_obj) if proc_obj else "N/A")
    )
    cmd = data.get("cmdline") or data.get("cmd_line") or "N/A"

  if p_name == "N/A":
    m_proc = re.search(
        r'<Data\s+Name=["\']Image["\']>\s*([^<]+)\s*</Data>',
        raw_text,
        re.IGNORECASE,
    )
    if m_proc:
      p_name = m_proc.group(1).strip()

  if cmd == "N/A":
    m_cmd = re.search(
        r'<Data\s+Name=["\']CommandLine["\']>\s*([^<]+)\s*</Data>',
        raw_text,
        re.IGNORECASE,
    )
    if m_cmd:
      cmd = m_cmd.group(1).strip()

  return p_name, cmd


def sanitize_command_line(cmd_line):
  if cmd_line == "N/A":
    return "N/A"
  cleaned = re.sub(r"https?://[^\s'\"]+", "[REDACTED_EXTERNAL_URL]", cmd_line)
  if len(cleaned) > 150:
    return cleaned[:147] + "..."
  return cleaned


def extract_action(data, raw_text, process_name, cmd_line):
  if isinstance(data, dict):
    act = (
        data.get("action")
        or data.get("eventName")
        or data.get("event_type")
        or (
            data.get("source_json", {}).get("eventName")
            if isinstance(data.get("source_json"), dict)
            else None
        )
    )
    if act:
      return act

  m_evt = re.search(
      r'<Data\s+Name=["\']EventName["\']>\s*([^<]+)\s*</Data>',
      raw_text,
      re.IGNORECASE,
  )
  if m_evt:
    return m_evt.group(1).strip()

  if process_name != "N/A":
    if "invoke-webrequest" in cmd_line.lower():
      return "Process Execution: Remote File Download (Invoke-WebRequest)"
    return f"Process Execution ({process_name})"

  return "Unknown Action"


def extract_target_object(data, raw_text):
  possible_targets = []
  if isinstance(data, dict):
    possible_targets.extend([
        data.get("target_user"),
        data.get("target_group"),
        data.get("target_member"),
        data.get("target_account"),
        data.get("target_object"),
        data.get("target_name"),
        data.get("group_name"),
        data.get("target"),
        data.get("hostname"),
        data.get("dns_domain"),
        data.get("ou"),
        (
            data.get("r7_context", {}).get("target_user")
            if isinstance(data.get("r7_context"), dict)
            else None
        ),
        (
            data.get("r7_context", {}).get("target_group")
            if isinstance(data.get("r7_context"), dict)
            else None
        ),
    ])

  m_target = re.findall(
      r'<Data\s+Name=["\'](?:TargetUserName|TargetGroup|WorkstationName|Computer)["\']>\s*([^<]+)\s*</Data>',
      raw_text,
      re.IGNORECASE,
  )
  possible_targets.extend(m_target)

  for val in possible_targets:
    if isinstance(val, str) and val.strip() and val.strip() != "N/A":
      return val.strip()
    elif isinstance(val, dict):
      name = (
          val.get("name")
          or val.get("username")
          or val.get("group_name")
          or val.get("id")
      )
      if name:
        return str(name).strip()

  return "N/A"


def get_event_details(raw_action, cmd_line=""):
  combined = (str(raw_action) + " " + str(cmd_line)).lower().strip()
  for key in EVENT_DICTIONARY:
    if key in combined:
      return EVENT_DICTIONARY[key]
  return {
      "title": f"Executed action '{raw_action}'",
      "example": (
          "(like executing an administrative command or cloud API request)"
      ),
      "why_fp": (
          "Authorized activity performed during regular business operations."
      ),
      "why_tp": (
          "Unauthorized or unusual action performed outside standard user"
          " scope."
      ),
      "impact": "May alter system configuration or access controls.",
  }


# 4. 📊 Unified Report Routing Engine
def print_report(raw_content, file_extension):
  # Check if file is an email header or .eml first
  if is_email_header(raw_content):
    print_email_report(raw_content)
    return

  # Otherwise parse as JSON / SIEM log
  data = None
  if file_extension in [".json", ".txt", ".log"]:
    try:
      data = json.loads(raw_content)
    except Exception:
      try:
        cleaned_content = raw_content.replace("\\", "\\\\")
        data = json.loads(cleaned_content)
      except Exception:
        data = None

  user = extract_user_universal(raw_content, data)
  process_name, cmd_line = extract_process_info(data, raw_content)
  clean_cmd = sanitize_command_line(cmd_line)
  raw_action = extract_action(data, raw_content, process_name, cmd_line)
  target = extract_target_object(data, raw_content)

  event_info = get_event_details(raw_action, cmd_line)
  known_admins = ["admin", "sys_admin", "administrator"]
  is_fp = any(adm in str(user).lower() for adm in known_admins)

  print(
      "\n================ 🛡️ PLAIN-ENGLISH TRIAGE REPORT 🛡️ ================"
  )
  print(f"ACTOR / USER      : {user}")
  print(f"EVENT DETECTED    : {event_info['title']}")
  print(f"SIMPLE EXAMPLE    : {event_info['example']}")
  print(f"PROCESS / SERVICE : {process_name}")
  print(f"COMMAND EXECUTED  : {clean_cmd}")
  print(f"TARGET / HOST     : {target}")
  print("-----------------------------------------------------------------")

  print("\n📜 WHAT HAPPENED:")
  print(f"• User '{user}' executed event '{raw_action}'.")
  print(f"• Initiating Process : {process_name}")
  print(f"• Command Executed   : {clean_cmd}")
  print(f"• Target Host / OU   : {target}")

  print("\n💥 POTENTIAL IMPACT:")
  print(f"• {event_info['impact']}")

  print("\n💡 ANALYSIS & CONTEXT:")
  print(
      "🟢 Why this could be NORMAL (False Positive):\n  "
      f" {event_info['why_fp']}"
  )
  print(
      "\n🔴 Why this could be DANGEROUS (True Positive):\n  "
      f" {event_info['why_tp']}"
  )

  print("\n🏷️ CLASSIFICATION:")
  if is_fp:
    print(
        "   [BENIGN / FALSE POSITIVE] -> Action initiated by an administrative"
        " account."
    )
  else:
    print(
        "   [SUSPICIOUS / POTENTIAL TRUE POSITIVE] -> Requires identity"
        " verification."
    )

  print("\n🎯 RECOMMENDED ACTION:")
  if is_fp:
    print(
        f"   INFORMATIONAL: Confirm with {user} if this was scheduled"
        " administrative work."
    )
  else:
    print(
        f"   ACTION REQUIRED: Contact {user} immediately to verify execution of"
        " this command."
    )
  print("=================================================================\n")


# 5. 🔄 Continuous Interactive Execution Loop
if __name__ == "__main__":
  print("=================================================================")
  print("      🛡️ CONTINUOUS SECURITY LOG TRIAGE TOOL INITIALIZED 🛡️      ")
  print("=================================================================")

  while True:
    try:
      file_path = (
          input("\nEnter log file path to analyze (or 'exit' to quit): ")
          .strip()
          .replace('"', "")
          .replace("'", "")
      )

      if file_path.lower() in ["exit", "quit", "q"]:
        print("\nExiting security triage tool. Goodbye!")
        break

      if not file_path:
        continue

      if not os.path.exists(file_path):
        print(
            f"\n❌ Error: File '{file_path}' not found. Please check the"
            " filename and try again."
        )
        continue

      _, ext = os.path.splitext(file_path)
      with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        print_report(f.read(), ext.lower())

    except (KeyboardInterrupt, EOFError):
      print("\n\nExiting security triage tool. Goodbye!")
      break
    except Exception as e:
      print(f"\n❌ Unexpected error analyzing file: {e}")