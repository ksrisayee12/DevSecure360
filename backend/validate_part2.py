import yaml
import re
from pathlib import Path

REQUIRED_FIELDS = [
    "rule_id", "language", "vuln_class", "severity", "cwe",
    "owasp", "cvss_score", "cvss_vector", "confidence",
    "issue", "message", "sources", "sinks", "sanitizers", "remediation"
]

ALLOWED_VULN_CLASSES = {
    "SQLi", "NoSQLi", "CMDi", "XSS", "SSTI", "SSRF", "XXE",
    "Path Traversal", "Open Redirect", "Deserialization", "Code Injection",
    "LDAP Injection", "XPath Injection", "Log Injection", "Hardcoded Secret",
    "Weak Crypto", "JWT Bypass", "Prototype Pollution", "Buffer Overflow",
    "Integer Overflow", "Format String", "Use After Free", "Memory Corruption",
    "Race Condition", "Null Pointer Dereference", "ReDoS", "CSRF",
    "Misconfiguration", "Cookie Security", "Mass Assignment",
    "File Upload", "Out-of-bounds Read", "Information Exposure",
    "Type Confusion", "DoS", "Cleartext Transmission", "Log Forging"
}

FORBIDDEN_SINKS = [
    "deprecated_function_", "DeprecatedMethod", "vulnerableSink",
    "fake_", "dummy_", "placeholder_", "_vuln", "vuln_func",
    "unsafe_func_", "test_sink_", "example_sink"
]

TENTATIVE_REQUIRED = {
    "c_use_after_free", "c_integer_overflow",
    "cpp_integer_overflow", "cpp_out_of_bounds_read",
    "go_csrf", "python_csrf", "javascript_csrf",
    "python_cookie_security", "javascript_cookie_security",
    "python_redos", "javascript_redos"
}

errors = []
seen_ids = {}

for f in sorted(Path("app/scanner/sast/rules").rglob("*.yaml")):
    try:
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"PARSE ERROR {f}: {e}")
        continue
    if not rule:
        errors.append(f"EMPTY FILE: {f}")
        continue

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"MISSING '{field}': {f.name}")
        elif rule[field] is None or rule[field] == "":
            errors.append(f"EMPTY '{field}': {f.name}")

    # Unique rule_id
    rid = str(rule.get("rule_id", "")).strip()
    if rid in seen_ids:
        errors.append(f"DUPLICATE rule_id '{rid}': {f.name} and {seen_ids[rid]}")
    else:
        seen_ids[rid] = f.name

    # vuln_class
    vc = str(rule.get("vuln_class", "")).strip()
    if vc not in ALLOWED_VULN_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f.name}")

    # confidence correctness
    conf = str(rule.get("confidence", "")).strip()
    if rid in TENTATIVE_REQUIRED and conf != "Tentative":
        errors.append(f"MUST BE Tentative (not '{conf}'): {f.name}")

    # Fabricated sinks
    sinks = rule.get("sinks", []) or []
    for sink in sinks:
        for forbidden in FORBIDDEN_SINKS:
            if forbidden.lower() in str(sink).lower():
                errors.append(f"FABRICATED SINK '{sink}': {f.name}")

    # Message length
    msg = str(rule.get("message", "")).strip()
    if len(msg) < 80:
        errors.append(f"MESSAGE TOO SHORT: {f.name}")

    # Remediation check
    rem = str(rule.get("remediation", "")).strip()
    if "validate and sanitize all user input" in rem.lower():
        errors.append(f"USELESS REMEDIATION: {f.name}")
    if len(rem) < 100:
        errors.append(f"REMEDIATION TOO SHORT: {f.name}")

    # Research evidence comment check
    raw = f.read_text(encoding="utf-8")
    if "# RESEARCH EVIDENCE" not in raw and f.stat().st_mtime > __import__('time').time() - 86400:
        errors.append(f"MISSING RESEARCH EVIDENCE COMMENT (new file): {f.name}")

print(f"Files checked: {len(list(Path('app/scanner/sast/rules').rglob('*.yaml')))}")
print(f"Rule IDs seen: {len(seen_ids)}")
print(f"Errors: {len(errors)}")
for e in errors:
    print(f"  ERROR: {e}")

if not errors:
    print("\nALL RULES PASS VALIDATION")
else:
    print(f"\nFIX ALL {len(errors)} ERRORS BEFORE REPORTING COMPLETION")
