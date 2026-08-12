#!/usr/bin/env python3
"""
SOC Investigation & Triage Engine v3.0
Evidence-first, vendor-neutral SOC investigation assistant.

Inputs:
  - local JSON/TXT/LOG/CSV/XML/EML/HTML/MSG path
  - pasted JSON (type PASTE_JSON)
  - authenticated investigation URL (API key requested only when needed)

Outputs:
  - human-readable TXT report
  - machine-readable JSON report

This version deliberately does NOT require analyst metadata when the evidence contains it.
It does not automatically close/modify alerts in external systems.
"""

from __future__ import annotations
import json, os, re, sys, hashlib
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

VERSION = "3.0.0"
OUT_ROOT = Path("soc_investigations")

SENSITIVE = {"api_key","apikey","token","access_token","refresh_token","password","secret","client_secret","authorization","cookie"}

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def redact_obj(x):
    if isinstance(x, dict):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE else redact_obj(v)) for k,v in x.items()}
    if isinstance(x, list):
        return [redact_obj(v) for v in x]
    return x

def flatten(d, prefix=""):
    out = {}
    if isinstance(d, dict):
        for k,v in d.items():
            p = f"{prefix}.{k}" if prefix else k
            out.update(flatten(v,p))
    elif isinstance(d, list):
        for i,v in enumerate(d):
            out.update(flatten(v,f"{prefix}[{i}]"))
    else:
        out[prefix] = d
    return out

def pick(flat, *names):
    wanted = [n.lower() for n in names]
    for k,v in flat.items():
        lk = k.lower()
        leaf = lk.split(".")[-1].replace("]","").split("[")[0]
        if leaf in wanted and v not in (None,"",[]):
            return v
    return None

def collect_values(flat, needles):
    vals=[]
    for k,v in flat.items():
        lk=k.lower()
        if any(n in lk for n in needles) and v not in (None,"",[]):
            vals.append(str(v))
    return vals

def extract(raw):
    flat = flatten(raw)
    def s(*n):
        v=pick(flat,*n)
        return str(v) if v is not None else "Unknown"
    return {
        "timestamp": s("timestamp","created_timestamp","context_timestamp"),
        "product": s("product","source_product","source_products"),
        "severity": s("severity_name","severity","original_severity"),
        "title": s("title","display_name","name"),
        "description": s("description"),
        "alert_id": s("alert_id","indicator_id","id","entry_id"),
        "user": s("user_principal","user_name","username","user"),
        "asset": s("hostname","host_name","asset","device"),
        "command": s("cmdline","command_line","command"),
        "filename": s("filename"),
        "filepath": s("filepath","file_path"),
        "parent": s("parent_details.filename","parent_process","parent_name"),
        "grandparent": s("grandparent_details.filename","grandparent_process"),
        "sha256": s("sha256"),
        "md5": s("md5"),
        "local_ip": s("local_ip","source_ip"),
        "external_ip": s("external_ip","destination_ip"),
        "status": s("status"),
        "rule": s("rule_instance_name","rule_name"),
        "scenario": s("scenario"),
        "prevalence": s("local_prevalence","global_prevalence"),
        "disposition": s("pattern_disposition_description","disposition"),
        "blocked": bool(any(str(v).lower()=="true" for k,v in flat.items() if any(x in k.lower() for x in ("process_blocked","kill_process","quarantine_file","quarantine_machine","operation_blocked")))),
        "iocs": collect_values(flat, ("ioc","indicator")),
    }

def analyze(e):
    reasons=[]
    risks=[]
    questions=[]
    severity=e["severity"].lower()
    cmd=e["command"].lower()
    fn=e["filename"].lower()
    rule=e["rule"].lower()
    parent=e["parent"].lower()
    grand=e["grandparent"].lower()

    benign_signals = 0
    suspicious_signals = 0

    if e["prevalence"].lower() in ("common","very common"):
        benign_signals += 1
        reasons.append("The observed executable/process has common prevalence.")
    if fn in ("cmdkey.exe","whoami.exe","ipconfig.exe","hostname.exe","systeminfo.exe"):
        benign_signals += 1
        reasons.append(f"{e['filename']} is a standard Windows utility.")
    if "cmdkey.exe" in cmd and "/list" in cmd:
        benign_signals += 2
        reasons.append("The command uses cmdkey.exe with /list, which lists stored credential entries rather than directly dumping credential material.")
    if "credential dumping" in rule:
        suspicious_signals += 1
        risks.append("The detection rule is specifically focused on credential-related activity.")
    if any(x in cmd for x in ("sekurlsa","lsass","procdump","comsvcs.dll","mimikatz")):
        suspicious_signals += 3
        risks.append("The command line contains a known credential-dumping pattern/tool.")
    if any(x in cmd for x in ("powershell -enc","frombase64string","downloadstring","iex(","invoke-webrequest","bitsadmin","certutil -urlcache")):
        suspicious_signals += 2
        risks.append("The command line contains a scripting/download pattern commonly requiring investigation.")
    if e["iocs"]:
        suspicious_signals += 1
        risks.append("IOC-related fields are present in the evidence.")
    if e["blocked"]:
        reasons.append("Endpoint telemetry indicates a prevention/response action was applied.")

    if suspicious_signals >= benign_signals + 2:
        verdict="LIKELY TRUE POSITIVE"
        confidence="High"
        action="Escalate to SecOps/IR for containment and deeper endpoint review."
    elif benign_signals >= suspicious_signals + 2:
        verdict="LIKELY FALSE POSITIVE / BENIGN"
        confidence="Medium"
        action="Validate the activity with the user/application owner; if authorized, close as benign/false positive."
    else:
        verdict="INCONCLUSIVE / NEEDS VALIDATION"
        confidence="Medium"
        action="Collect additional process-tree, user activity and endpoint telemetry before closure."

    if "cmdkey.exe" in cmd:
        questions.append("Did the user intentionally run cmdkey /list around the alert timestamp?")
    if e["parent"] not in ("Unknown","unknown"):
        questions.append(f"Was the parent application ({e['parent']}) expected and approved on this endpoint?")
    questions.append("Is there any related authentication failure, privilege escalation, lateral movement, or outbound activity around the same timestamp?")
    if e["severity"].lower() == "high":
        questions.append("Confirm whether the business/user context justifies the detected behavior before downgrading or closing.")

    return {
        "verdict":verdict, "confidence":confidence, "reasons":reasons,
        "risks":risks, "recommended_action":action, "questions":questions
    }

def load_local(path):
    p=Path(path)
    data=p.read_text(encoding="utf-8", errors="replace")
    if p.suffix.lower()==".json":
        return json.loads(data), data
    try:
        return json.loads(data), data
    except Exception:
        return {"raw_text":data}, data

def parse_pasted():
    print("\nPaste complete JSON. Finish with Ctrl+D (Linux/Codespaces) or Ctrl+Z then Enter (Windows).")
    data=sys.stdin.read()
    return json.loads(data), data

def fetch_url(url):
    try:
        import requests
    except ImportError:
        print("requests is not installed. Use JSON/file input, or install requests.")
        return None, None
    key=os.environ.get("SOC_API_KEY") or os.environ.get("R7KEY")
    if not key:
        key=input("API key/token (ENTER to skip remote access): ").strip()
    if not key:
        return None, None
    # Generic bearer authentication; vendor-specific endpoints must be configured separately.
    r=requests.get(url, headers={"Authorization":f"Bearer {key}","Accept":"application/json"}, timeout=30)
    if r.status_code >= 400:
        print(f"Remote access failed: HTTP {r.status_code}")
        return None, None
    return r.json(), r.text

def make_report(raw, source, analyst):
    e=extract(raw); a=analyze(e)
    inv_id = e["alert_id"] if e["alert_id"]!="Unknown" else hashlib.sha1((source+now()).encode()).hexdigest()[:12]
    folder=OUT_ROOT / f"INV-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{inv_id[-8:]}"
    folder.mkdir(parents=True, exist_ok=True)

    closure=(f"Disposition: {a['verdict']}. {a['recommended_action']} "
             f"Evidence reviewed included the alert metadata and available process/context telemetry. "
             f"No external system action was performed by this tool.")

    report={
        "engine_version":VERSION,"generated_utc":now(),"analyst":analyst or "Unknown",
        "source":source,"investigation":e,"analysis":a,"closure_comments":closure,
        "raw_evidence":redact_obj(raw)
    }
    (folder/"investigation_report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    lines=[
        f"SOC INVESTIGATION REPORT v{VERSION}","="*78,
        f"Generated UTC : {report['generated_utc']}",f"Analyst       : {report['analyst']}",
        f"Source        : {source}","",
        "EXECUTIVE VERDICT","-"*78,
        f"Verdict       : {a['verdict']}",f"Confidence     : {a['confidence']}",
        f"Severity       : {e['severity']}",f"Alert          : {e['title']}",
        f"Alert ID       : {e['alert_id']}",f"User           : {e['user']}",
        f"Asset          : {e['asset']}","",
        "WHAT HAPPENED","-"*78,
        e["description"],"",
        "EVIDENCE","-"*78,
        f"Command        : {e['command']}",f"Process         : {e['filename']}",
        f"Parent         : {e['parent']}",f"Grandparent    : {e['grandparent']}",
        f"Rule           : {e['rule']}",f"Prevalence     : {e['prevalence']}",
        f"Disposition    : {e['disposition']}",f"Blocked        : {e['blocked']}","",
        "WHY","-"*78,
    ]
    lines += [f"- {x}" for x in a["reasons"]] or ["- No strong benign indicators identified."]
    if a["risks"]:
        lines += ["","RISKS / CONCERNS","-"*78] + [f"- {x}" for x in a["risks"]]
    lines += ["","LAYMAN'S EXPLANATION","-"*78,
              f"The alert was generated because {e['title']} was detected on {e['asset']}.",
              f"The observed process was {e['filename']} and the command was: {e['command']}.",
              a["recommended_action"],
              "","FOLLOW-UP QUESTIONS","-"*78]
    lines += [f"- {q}" for q in a["questions"]]
    lines += ["","RECOMMENDED ASSIGNMENT","-"*78,
              "Primary: SecOps / Security Operations",
              "Escalate to Incident Response if malicious activity or unauthorized credential access is confirmed.",
              "","CLOSURE COMMENTS","-"*78,closure]
    lines += ["","NOTE","-"*78,"This engine provides evidence-based triage assistance. Analyst approval is required before closure or any response action."]
    (folder/"investigation_report.txt").write_text("\n".join(lines),encoding="utf-8")
    return folder, report

def main():
    print("="*78)
    print(f"SOC Investigation & Triage Engine v{VERSION}")
    print("ONE-INPUT / EVIDENCE-FIRST MODE")
    print("URL requires authentication only when remote access is needed.")
    print("JSON/file evidence does not require an API key.")
    print("Type 'exit' to quit.")
    analyst=input("\nAnalyst name [ENTER for local account]: ").strip()
    source=input("\nPaste URL, local file path, or type PASTE_JSON: ").strip()
    if source.lower()=="exit": return
    try:
        if source.upper()=="PASTE_JSON":
            raw,_=parse_pasted(); src="Pasted JSON"
        elif re.match(r"^https?://",source):
            raw,_=fetch_url(source)
            if raw is None:
                print("No remote evidence retrieved. Provide exported JSON instead.")
                return
            src=source
        else:
            raw,_=load_local(source); src=source
        folder,report=make_report(raw,src,analyst)
        a=report["analysis"]
        print("\n"+"="*78)
        print(f"VERDICT      : {a['verdict']}")
        print(f"CONFIDENCE   : {a['confidence']}")
        print(f"ASSIGNMENT   : SecOps / Security Operations")
        print(f"TXT REPORT   : {folder/'investigation_report.txt'}")
        print(f"JSON REPORT  : {folder/'investigation_report.json'}")
        print("="*78)
    except json.JSONDecodeError as ex:
        print(f"ERROR: Invalid JSON: {ex}")
    except Exception as ex:
        print(f"ERROR: {type(ex).__name__}: {ex}")

if __name__=="__main__":
    main()
