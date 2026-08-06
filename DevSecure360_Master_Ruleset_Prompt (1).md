# DevSecure360 SAST Engine — Master Ruleset Construction Prompt
# FOR HIGH-CAPABILITY MODEL USE
# Version: Final | Based on full audit of 5 successive ruleset iterations
#
# READ THIS ENTIRE DOCUMENT BEFORE DOING ANYTHING.
# Every section is mandatory. Nothing here is optional guidance.

---

## 1. WHAT YOU ARE BUILDING

You are constructing the YAML ruleset for DevSecure360 — a proprietary SAST (Static
Application Security Testing) engine that is part of a standalone commercial security
scanning SaaS platform. This engine replaces Semgrep, Bandit, and all other third-party
scanners. Every rule you write becomes a detection rule in a real production security product
used by real customers to secure real applications.

The ruleset covers 8 languages:
Python, JavaScript, Java, PHP, Go, C#, C, C++

The target is 1,000 to 1,500 total rules.
The current state is 151 rules.
Rules are added in batches of exactly 30 per run to maintain focus and accuracy.

---

## 2. THE HISTORY OF THIS RULESET — READ TO UNDERSTAND PAST FAILURES

This ruleset has gone through 5 iterations. Each iteration introduced new bugs.
Understanding what went wrong is mandatory so you do not repeat those mistakes.

### Failure 1 — Fabricated Sinks (Iterations 1-2)
The agent invented function names that do not exist in real codebases:
- `deprecated_function_10(` — not a real Go function
- `DeprecatedMethod10(` — not a real C# method
- `vulnerableSink(` — invented
These rules never matched any real code. They inflated the rule count while
providing zero detection capability. Over 200 such rules were created and deleted.

**The fix that was enforced:** Every sink must be verified against a real URL
(CodeQL, Semgrep, or official language documentation) before being written.

### Failure 2 — Wrong vuln_class Values (Iterations 3-5)
Multiple incorrect `vuln_class` values were introduced:
- `Type Confusion` used for Python/Java/PHP/C# reflection vulnerabilities
  (WRONG — Type Confusion is a C/C++ memory safety issue, CWE-843)
  (CORRECT — reflection-based code execution is `Code Injection`, CWE-94)
- `Log Forging` used across JS, Go, PHP, C# log injection rules
  (WRONG — not in the allowed list)
  (CORRECT — the correct class is `Log Injection`)
- `Best Practice` used for 100 Go and 100 C# placeholder rules
  (WRONG — not a vulnerability class, rules were fabricated)
- `Mass Assignment`, `Out-of-bounds Read`, `Cleartext Transmission`, `Information Exposure`
  used without being in the allowed list (later these were formally added)

**The fix that was enforced:** A strict allowed list with an automated validator.

### Failure 3 — Missing Required Fields (Iteration 1-3)
941 out of 1,042 rules were missing `owasp`, `message`, and `remediation` fields.
When remediation existed, it was universally: "Validate and sanitize all user input."
This is useless. It does not tell a developer what to actually do.

**The fix that was enforced:** All 15 fields are required. Remediation must include
a before/after code example. Message must be 80+ chars specific to the sink.

### Failure 4 — Wrong Confidence Values (Iterations 2-4)
Memory analysis rules (buffer overflow, integer overflow, use-after-free) were marked
`confidence: Confirmed`. This is technically wrong — the current engine cannot confirm
these vulnerabilities without runtime type size and pointer state information. These
rules should be `confidence: Tentative`.

Similarly, structural pattern rules (CSRF, Cookie Security, ReDoS, missing headers)
were marked `Confirmed` when they are pattern-based heuristics requiring manual review.

**The fix that was enforced:** Specific rule types are permanently required to be Tentative.

### Failure 5 — SSA Not Wired, Legacy Fallback Seeding All Parameters (Architecture)
This is a code-level issue, not a YAML issue, but it is relevant context:
The taint engine's legacy fallback seeds EVERY function parameter as tainted, causing
high false positive rates. This is gated behind a flag. Do not design rules that rely
on this behavior — design rules that work with proper taint analysis only.

### Failure 6 — Sanitizers in Sources Block, Sources in Sinks Block
`sqli_001.yaml` had `%s` and `?` (which are sanitizers) in the `sources:` block.
PHP rules had `prepare(` and `bindParam(` (which are sanitizers) in the `sinks:` block.
The three blocks have strict definitions. Do not confuse them.

### Failure 7 — No Research Evidence (All iterations until enforced)
85 of 87 original rules have no documented research source. When asked where sinks
came from, the answer was "from memory." Memory is not a reliable source for security
function names. The research evidence comment block is now mandatory on every rule.

### Failure 8 — Copy-Paste Source Lists Across Unrelated Vuln Classes
The same 35-item HTTP source list was pasted into every Python rule including
`Weak Crypto` and `Hardcoded Secret` which are pattern-based rules requiring
`sources: []`. Sources must be relevant to the specific vulnerability class.

---

## 3. CURRENT STATE OF THE RULESET

```
Total rules: 304
```

Per language:
```
Python:     57 rules
JavaScript: 56 rules
Java:       30 rules
PHP:        31 rules
Go:         37 rules
C#:         42 rules
C:          23 rules
C++:        28 rules
```

### Mandatory Audit for Recurrence of Historical Bug Patterns (Do This First)

The specific bug instances previously found in this ruleset (a cookie-security rule
wrongly marked `Confirmed`, reflection rules wrongly classed as `Type Confusion`, and
log-injection rules wrongly classed as `Log Forging`) have already been corrected.
Do not assume the ruleset is clean, however — before doing any new work, scan every
existing rule file for any remaining or reintroduced instances of these same bug
patterns, and correct any that you find:

- Any rule with `confidence: Confirmed` where the vuln_class is a structural/
  absence-based or heuristic pattern (e.g. Cookie Security, CSRF, ReDoS, missing
  security headers) — should be `confidence: Tentative`.
- Any reflection-related rule using `vuln_class: Type Confusion` — should be
  `vuln_class: Code Injection`, since reflection driven by user input results in
  code execution, not a memory-safety type confusion issue.
- Any log-injection rule using `vuln_class: Log Forging` — this value is not on
  the allowed list; should be `vuln_class: Log Injection`.

If the audit finds any such instances, fix them before proceeding with new rule
batches. If none are found, note that the audit was performed and passed clean.

### 85 Rules Missing Research Evidence Comment (Fix During Expansion)
All rules written before the research evidence requirement was enforced lack the
`# RESEARCH EVIDENCE` comment block. Add these during expansion when touching
those files, or in a dedicated cleanup batch.

---

## 4. THE MANDATORY RESEARCH PROCESS

This is the most important section. Read it completely.

Every sink in every rule must be verified before being written. You have access to
web search. Use it. This is not optional.

### Step 1 — Verify the CWE at MITRE
URL: `https://cwe.mitre.org/data/definitions/{NUMBER}.html`

Confirm:
- The vulnerability class name matches the official CWE title
- The affected languages match what you are writing for
- The CVSS severity matches your planned assignment

### Step 2 — Find Real Sinks in CodeQL
CodeQL is GitHub's production SAST engine. Their sink definitions are maintained by
professional security engineers and are exactly what we want to match.

Search paths:
- `https://codeql.github.com/codeql-standard-libraries/python/`
- `https://codeql.github.com/codeql-standard-libraries/javascript/`
- `https://codeql.github.com/codeql-standard-libraries/java/`
- `https://codeql.github.com/codeql-standard-libraries/go/`
- `https://codeql.github.com/codeql-standard-libraries/csharp/`
- `https://codeql.github.com/codeql-standard-libraries/cpp/`
- GitHub: `https://github.com/github/codeql` → browse by language → security

What to extract: The exact function names in their `isSink()` methods or sink classes.
These are the verified real sinks. Copy them exactly.

### Step 3 — Cross-Reference With Semgrep Registry
Semgrep's public rule registry has thousands of production security rules.
URL: `https://semgrep.dev/r`
Filter by: language + vulnerability class

What to extract: The `patterns:` or `pattern:` fields that identify the dangerous call.
The function names in those patterns are verified real sinks.

### Step 4 — Find Sources in Official Framework Documentation
Sources must come from official docs, not memory.

Python Flask:    `https://flask.palletsprojects.com/en/latest/api/#flask.Request`
Python Django:   `https://docs.djangoproject.com/en/stable/ref/request-response/`
Python FastAPI:  `https://fastapi.tiangolo.com/tutorial/query-params/`
Node.js Express: `https://expressjs.com/en/api.html#req`
Node.js Fastify: `https://fastify.dev/docs/latest/Reference/Request/`
Java Spring:     `https://docs.spring.io/spring-framework/docs/current/javadoc-api/`
Java Servlet:    `https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletRequest.html`
PHP globals:     `https://www.php.net/manual/en/reserved.variables.php`
Go net/http:     `https://pkg.go.dev/net/http#Request`
Go Gin:          `https://pkg.go.dev/github.com/gin-gonic/gin#Context`
ASP.NET Core:    `https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.httprequest`

### Step 5 — Find Sanitizers in OWASP Cheat Sheets
URL: `https://cheatsheetseries.owasp.org/`

Every major vulnerability class has a dedicated cheat sheet with verified sanitizers:
- SQL Injection Prevention: `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`
- XSS Prevention: `https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html`
- Command Injection: `https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html`
- Path Traversal: `https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html`
- LDAP Injection: `https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html`
- XXE Prevention: `https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html`
- Deserialization: `https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html`
- Cryptographic Storage: `https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html`
- Transport Layer: `https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html`
- CSRF Prevention: `https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html`

### Step 6 — Record Evidence in Every File
Every new rule file must start with this comment block:

```yaml
# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/{NUMBER}.html
# CodeQL Source:   {exact URL to the QL file or concept} | or "Not applicable — pattern-based"
# Semgrep Source:  {exact URL to the rule} | or "Not applicable — pattern-based"
# OWASP Cheat:     {exact URL to the cheat sheet}
# Verification:    {One sentence: what package does this sink belong to, and
#                   which of the above sources confirmed it is a real dangerous function}
```

If you cannot find a real CodeQL or Semgrep URL for a sink, that sink is unverified.
Do not write unverified sinks. Either find a different source or omit the sink.

---

## 5. PHASE 0 — FIX EXISTING BUGS BEFORE ANY EXPANSION

Complete this phase first. Do not create any new rules until all bugs are fixed.

### Fix 1 of 3
File: `rules/javascript/js_cookie_security.yaml`
```yaml
# CHANGE:
confidence: Confirmed
# TO:
confidence: Tentative
```

### Fix 2 of 3
Files: `rules/csharp/csharp_insecure_reflection.yaml`,
       `rules/java/java_insecure_reflection.yaml`,
       `rules/php/php_insecure_reflection.yaml`,
       `rules/python/python_insecure_reflection.yaml`
```yaml
# CHANGE in all 4 files:
vuln_class: Type Confusion
# TO:
vuln_class: Code Injection
```

### Fix 3 of 3
Files: `rules/csharp/csharp_log_injection.yaml`,
       `rules/go/go_log_injection.yaml`,
       `rules/javascript/js_log_injection.yaml`,
       `rules/php/php_log_injection.yaml`
```yaml
# CHANGE in all 4 files:
vuln_class: Log Forging
# TO:
vuln_class: Log Injection
```

### Phase 0 Verification
Run this Python script. Output must be `PHASE 0 COMPLETE` before proceeding:

```python
import yaml
from pathlib import Path
errors = []
for f in Path("rules").rglob("*.yaml"):
    r = yaml.safe_load(f.read_text(encoding="utf-8"))
    if not r: continue
    vc = str(r.get("vuln_class","")).strip()
    rid = str(r.get("rule_id","")).strip()
    conf = str(r.get("confidence","")).strip()
    if vc == "Type Confusion":
        errors.append(f"Bug2 still present: {f.name}")
    if vc == "Log Forging":
        errors.append(f"Bug3 still present: {f.name}")
    if rid == "js_cookie_security" and conf != "Tentative":
        errors.append(f"Bug1 still present: {f.name}")
if not errors:
    print("PHASE 0 COMPLETE")
else:
    [print(f"ERROR: {e}") for e in errors]
```

---

## 6. THE COMPLETE YAML SCHEMA

Every rule file — existing and new — must conform to this schema exactly.
All 15 fields are required. No field may be absent or empty.

```yaml
# RESEARCH EVIDENCE                          ← MANDATORY COMMENT BLOCK
# CWE Source:      {URL}
# CodeQL Source:   {URL or "Not applicable"}
# Semgrep Source:  {URL or "Not applicable"}
# OWASP Cheat:     {URL}
# Verification:    {One sentence confirming sinks are real and sourced from above}

rule_id: {language}_{vuln_short}_{descriptor}
# Rules:
# - Globally unique across ALL files in ALL language directories
# - snake_case only. No spaces. No uppercase.
# - Format: language prefix + vuln abbreviation + descriptor
# - Examples: python_sqli_sqlalchemy, go_cmdi_shell_exec, cpp_bof_strcpy
# - Check for collisions before assigning: no two files may share a rule_id

language: python | javascript | java | php | go | csharp | c | cpp
# Exactly one of these 8 values. Lowercase.

vuln_class: {see Section 7 — Allowed Values}
# Must be exactly one value from the allowed list in Section 7.
# No variations. No trailing whitespace. No typos.

severity: Critical | High | Medium | Low
# Map from CVSS score:
# Critical = 9.0-10.0  |  High = 7.0-8.9  |  Medium = 4.0-6.9  |  Low = 0.1-3.9

cwe: CWE-{number}
# Must be the correct CWE from mitre.org. Never use CWE-1000 (that is a category).
# Reference: https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html

owasp: A{N}:{year}-{Category Name}
# Must be the correct OWASP Top 10 2021 category:
# A01:2021-Broken Access Control
# A02:2021-Cryptographic Failures
# A03:2021-Injection
# A04:2021-Insecure Design
# A05:2021-Security Misconfiguration
# A06:2021-Vulnerable and Outdated Components
# A07:2021-Identification and Authentication Failures
# A08:2021-Software and Data Integrity Failures
# A09:2021-Security Logging and Monitoring Failures
# A10:2021-Server-Side Request Forgery

cvss_score: {float between 0.0 and 10.0}
# Correct CVSS v3.1 base score. Common values:
# Network-exploitable injection (SQLi, CMDi, RCE, Deserialization): 9.8
# SSRF with full read/write: 8.6
# Path Traversal: 7.5  |  XXE: 7.5  |  LDAP Injection: 7.5
# Stored XSS: 6.1  |  Reflected XSS: 6.1
# Weak Crypto (hash): 5.9  |  Hardcoded Secret: 7.5
# Buffer Overflow (RCE possible): 8.8  |  Format String: 8.8
# Integer Overflow: 7.5  |  Use After Free: 8.8

cvss_vector: CVSS:3.1/{AV}:{AC}:{PR}:{UI}:{S}:{C}:{I}:{A}
# Valid CVSS v3.1 vector. Most network injection attacks:
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → score 9.8

confidence: Confirmed | Probable | Tentative
# Definitions:
#   Confirmed  = taint engine proves data flows source → sink with no sanitizer
#   Probable   = strong structural pattern, not full taint proof
#   Tentative  = heuristic, CFG-based, or absence-detection; requires manual review
#
# MANDATORY Tentative — never mark these Confirmed:
#   Buffer Overflow, Integer Overflow, Use After Free, Format String (C/C++)
#   Null Pointer Dereference, Race Condition, Memory Corruption
#   CSRF, Cookie Security, ReDoS, Misconfiguration
#   Missing security headers, Session management patterns
#   Any rule that detects the ABSENCE of something (no middleware, no flag, no header)
#
# Confirmed is correct for:
#   All injection rules with clear source→sink taint path (SQLi, CMDi, XSS, etc.)
#   Deserialization when source reaches sink directly
#   Hardcoded Secret (pattern match on literal string assignment)
#   Weak Crypto (pattern match on specific insecure function call)

issue: "{one precise sentence}"
# Names the specific function AND the specific vulnerability.
# Good: "SQL Injection via Hibernate session.createQuery() with string concatenation"
# Good: "Command Injection via subprocess.call() with shell=True and user input"
# Bad:  "SQL Injection detected"
# Bad:  "Potential security issue"
# Bad:  "SQL Injection (CWE-89)"

message: |-
  {Minimum 2 sentences, minimum 80 characters total.}
  {Sentence 1: Mechanically what happens — where does user input enter, how does it flow,
               what dangerous operation receives it}
  {Sentence 2: What can an attacker do with this — be specific, name attack outcomes}
  {Optional sentence 3: Why this specific code pattern is dangerous}
# MUST be specific to THIS rule's sink. Never copy-paste from another rule.
# Good:
#   "User-controlled data from request.args flows directly into cursor.execute()
#    without parameterization. An attacker can inject arbitrary SQL to read all
#    database tables, modify or delete data, or execute OS commands via xp_cmdshell."
# Bad:
#   "This is a SQL injection vulnerability."
# Bad: (copy-pasted from another rule — same text, different sink)

sources:
# DEFINITION: The specific API calls or variable accesses through which
# user-controlled data enters the program in this language and framework.
#
# RULES:
# - Only include sources RELEVANT to this specific vulnerability class
# - Weak Crypto → sources: []  (no HTTP input needed — detect the dangerous call itself)
# - Hardcoded Secret → sources: []  (pattern-based — no HTTP input)
# - ReDoS → sources: []  (pattern-based on regex string literal)
# - CSRF → sources: []  (structural/absence detection)
# - Cookie Security → sources: []  (structural/absence detection)
# - Missing Headers → sources: []  (structural/absence detection)
# - C/C++ → use stdin/argv/env/network recv — NOT Flask/Django HTTP sources
# - Do NOT put sanitizers or sinks in this block
  - real_http_source_function(

sinks:
# DEFINITION: The specific function calls or operations where the vulnerability
# is triggered when reached with tainted/user-controlled data.
#
# RULES:
# - Every sink must be verifiable via a URL in the research evidence comment
# - Sinks must be specific enough to not match safe usage
# - Do NOT put sources or sanitizers in this block
# - ReDoS → sinks: []  (detect the regex pattern itself, not a function call)
# - CSRF → sinks: []  (detect absence of middleware, not a dangerous call)
# - Pattern-based rules → sinks: []
  - real_dangerous_function(

sanitizers:
# DEFINITION: The specific functions or patterns that, when applied to tainted
# data BEFORE it reaches the sink, neutralize this specific vulnerability.
#
# RULES:
# - Must be the CORRECT sanitizer for THIS specific vuln class
# - SQLi sanitizer ≠ XSS sanitizer ≠ CMDi sanitizer ≠ Path Traversal sanitizer
# - If no real sanitizer exists for this vuln class in this language: sanitizers: []
# - Do NOT put sources or sinks in this block
# - Do NOT put generic validators here (e.g., "validate_input(" is not a sanitizer)
  - real_sanitizer_function(

remediation: |-
  {Minimum 3 sentences, minimum 100 characters total.}
  {Must include:}
  {1. What to STOP doing — name the specific vulnerable pattern}
  {2. What to DO INSTEAD — name the specific safe alternative or function}
  {3. A concrete code example showing UNSAFE and SAFE patterns in THIS language}
  {4. Optional: reference to OWASP Cheat Sheet URL}
# MUST NOT be: "Validate and sanitize all user input."
# MUST NOT be: "Ensure proper input validation."
# MUST NOT be: "Follow secure coding best practices."
# MUST include a before/after code snippet.
# Good structure:
#   "Replace string concatenation in SQL with parameterized queries. The database
#    driver handles escaping automatically.
#
#    UNSAFE:  cursor.execute('SELECT * WHERE name=' + user_name)
#    SAFE:    cursor.execute('SELECT * WHERE name=%s', (user_name,))
#
#    See OWASP SQL Injection Prevention Cheat Sheet for complete guidance."
```

---

## 7. ALLOWED VULN_CLASS VALUES

Use exactly these strings. No variations. No trailing whitespace. No typos.
The validator enforces this list strictly.

```
Injection Vulnerabilities:
  SQLi                XSS                 CMDi
  NoSQLi              SSTI                SSRF
  XXE                 LDAP Injection      XPath Injection
  Log Injection       Code Injection      Open Redirect
  Prototype Pollution

Access and Auth:
  Path Traversal      CSRF                JWT Bypass
  Cookie Security     Mass Assignment     File Upload

Cryptography:
  Weak Crypto         Hardcoded Secret    Cleartext Transmission

Deserialization:
  Deserialization

Memory Safety (C/C++ primarily):
  Buffer Overflow     Integer Overflow    Format String
  Use After Free      Memory Corruption   Race Condition
  Null Pointer Dereference                Out-of-bounds Read

Application Logic:
  ReDoS               DoS                 Information Exposure
  Misconfiguration
```

Values explicitly forbidden (caused bugs in past iterations):
```
FORBIDDEN:
  Type Confusion      ← use Code Injection for reflection vulns
  Log Forging         ← use Log Injection
  Best Practice       ← not a vulnerability class
  Injection           ← too generic, use SQLi/CMDi/LDAP Injection/etc.
  Security Issue      ← not a vulnerability class
  Vulnerability       ← not a vulnerability class
```

---

## 8. SOURCE REFERENCE TABLES BY LANGUAGE

Use these exact API calls as sources. They are verified from official documentation.
Do not add sources you cannot verify from official docs.

### Python Sources

Flask HTTP:
```
request.args.get(     request.args[
request.form.get(     request.form[
request.json          request.get_json(
request.data          request.values.get(
request.cookies.get(  request.headers.get(
request.files.get(    request.stream
```

Django HTTP:
```
request.GET.get(      request.GET[
request.POST.get(     request.POST[
request.body          request.META.get(
request.COOKIES.get(  request.FILES.get(
request.headers.get(
```

FastAPI:
```
Query(    Body(    Form(    Path(    Header(    Cookie(
```

System:
```
os.environ.get(    os.environ[    os.getenv(
sys.argv[          input(
```

### JavaScript / Node.js Sources

Express.js:
```
req.query.          req.query[
req.body.           req.body[
req.params.         req.params[
req.headers[        req.get(
req.cookies.        req.cookies[
```

Fastify:
```
request.query.      request.body.
request.params.     request.headers[
```

System:
```
process.env.        process.argv[
```

### Java Sources

Servlet/JSP:
```
request.getParameter(      request.getParameterValues(
request.getHeader(         request.getHeaders(
request.getCookies(        request.getInputStream(
request.getReader(         request.getQueryString(
request.getPathInfo(
```

Spring MVC Annotations (parameter-level sources):
```
@RequestParam    @PathVariable    @RequestBody
@RequestHeader   @CookieValue
```

### PHP Sources
```
$_GET[            $_POST[           $_REQUEST[
$_COOKIE[         $_SERVER[         $_FILES[
getallheaders(    file_get_contents('php://input')
filter_input(
```

### Go Sources

net/http:
```
r.URL.Query().Get(    r.FormValue(
r.PostFormValue(      r.Header.Get(
r.Cookie(             r.Body
```

Gin:
```
c.Query(    c.DefaultQuery(    c.Param(
c.PostForm( c.GetHeader(       c.Cookie(
c.ShouldBindJSON(              c.BindJSON(
```

Echo:
```
c.QueryParam(    c.FormValue(    c.Param(
c.Request().Header.Get(         c.Cookie(
```

System:
```
os.Getenv(    os.Args[
```

### C# Sources

ASP.NET WebForms:
```
Request.QueryString[    Request.Form[
Request.Cookies[        Request.Headers[
Request.InputStream     Request.Url
```

ASP.NET Core:
```
HttpContext.Request.Query[      HttpContext.Request.Form[
HttpContext.Request.Headers[    HttpContext.Request.Cookies[
HttpContext.Request.Body
```

ASP.NET Core Annotations:
```
[FromQuery]    [FromBody]    [FromForm]
[FromRoute]    [FromHeader]
```

System:
```
Console.ReadLine(    Environment.GetCommandLineArgs(
Environment.GetEnvironmentVariable(
```

### C Sources
```
gets(         fgets(        scanf(        fscanf(
sscanf(       read(         recv(         recvfrom(
getenv(       argv[         getchar(      fread(
```

### C++ Sources
```
std::cin >>                  std::getline(
getenv(                      argv[
recv(                        read(
boost::asio (socket reads)
```

---

## 9. SINK REFERENCE TABLES BY LANGUAGE

These are verified real sinks. All verified against CodeQL, Semgrep, or official docs.

### Python Sinks by Vuln Class

SQLi:
```
cursor.execute(        cursor.executemany(    connection.execute(
conn.execute(          db.execute(            db.session.execute(
engine.execute(        session.execute(       .raw(
```

CMDi:
```
subprocess.call(       subprocess.run(        subprocess.Popen(
subprocess.check_output(  subprocess.check_call(  os.system(
os.popen(              os.execv(              os.execve(
os.spawnv(             asyncio.create_subprocess_shell(
```

XSS (server-side):
```
render_template_string(    Markup(    jinja2.Template(
```

Path Traversal:
```
open(          os.open(       pathlib.Path(    io.open(
zipfile.ZipFile(    tarfile.open(    shutil.copy(
flask.send_file(    send_from_directory(
```

SSRF:
```
requests.get(      requests.post(     requests.put(
requests.Session(  urllib.request.urlopen(
urllib.request.urlretrieve(   httpx.get(
httpx.Client(      aiohttp.ClientSession(   urllib3.PoolManager(
```

SSTI:
```
render_template_string(    jinja2.Template(
jinja2.Environment(        mako.template.Template(
```

Deserialization:
```
pickle.loads(      pickle.load(       yaml.load(
marshal.loads(     jsonpickle.decode( dill.loads(
```

Code Injection:
```
eval(    exec(    compile(
```

LDAP Injection:
```
ldap3.Connection.search(    ldap.search_s(
```

XXE:
```
lxml.etree.parse(                      lxml.etree.fromstring(
xml.etree.ElementTree.parse(           xml.sax.parseString(
defusedxml (safe — use as sanitizer)
```

Weak Crypto (pattern-based, sources: []):
```
hashlib.md5(    hashlib.sha1(    Crypto.Cipher.DES(
Crypto.Cipher.RC4(    random.random(    random.randint(
```

### JavaScript Sinks by Vuln Class

SQLi:
```
connection.query(    pool.query(    db.query(
sequelize.query(     knex.raw(      knex.whereRaw(
knex.havingRaw(      typeorm_query_builder_with_concat
```

NoSQLi:
```
collection.find(    collection.findOne(    Model.find(
Model.findOne(      Model.where(           db.collection(.where(
```

CMDi:
```
child_process.exec(     child_process.execSync(
child_process.spawn(    child_process.spawnSync(
child_process.execFile(
```

XSS:
```
innerHTML =             outerHTML =
document.write(         document.writeln(
eval(                   new Function(
dangerouslySetInnerHTML res.send(    res.write(
```

Path Traversal:
```
fs.readFile(      fs.readFileSync(    fs.writeFile(
fs.createReadStream(    res.sendFile(    require(
```

Code Injection:
```
eval(    new Function(    vm.runInNewContext(
vm.runInThisContext(     vm.Script(
```

SSRF:
```
http.get(    http.request(    https.get(
https.request(    axios.get(    axios.post(
fetch(       got(             request(
```

Prototype Pollution:
```
_.merge(    _.defaultsDeep(    Object.assign(
jQuery.extend(    merge(        extend(
```

Weak Crypto (pattern-based, sources: []):
```
crypto.createHash('md5'     crypto.createHash('sha1'
crypto.createCipher('des    Math.random(
```

### Java Sinks by Vuln Class

SQLi:
```
statement.execute(          statement.executeQuery(
statement.executeUpdate(    entityManager.createNativeQuery(
entityManager.createQuery(  session.createQuery(
session.createSQLQuery(     jdbcTemplate.execute(
jdbcTemplate.query(         jdbcTemplate.update(
```

CMDi:
```
Runtime.getRuntime().exec(    ProcessBuilder(
new ProcessBuilder(
```

XSS:
```
response.getWriter().write(    response.getWriter().print(
response.getWriter().println(  out.println(
```

XXE:
```
DocumentBuilderFactory.newInstance(    SAXParserFactory.newInstance(
XMLInputFactory.newInstance(           TransformerFactory.newInstance(
```

Deserialization:
```
ObjectInputStream(    readObject(    readUnshared(
XStream.fromXML(      new Yaml().load(    ObjectMapper.readValue(
```

Path Traversal:
```
new File(    Paths.get(    FileInputStream(
FileOutputStream(    Files.readAllBytes(    Files.write(
```

Log Injection / Log4Shell:
```
logger.info(    logger.error(    logger.debug(
logger.warn(    logger.fatal(    log.info(
log.error(
```

JNDI Injection (Code Injection):
```
InitialContext.lookup(    context.lookup(
dirContext.lookup(        ctx.lookup(
```

SSRF:
```
new URL(.openConnection(    URL.openStream(
HttpClient.newBuilder(      RestTemplate.getForEntity(
RestTemplate.postForEntity( WebClient.create(
```

Weak Crypto (pattern-based, sources: []):
```
MessageDigest.getInstance("MD5"     MessageDigest.getInstance("SHA-1"
Cipher.getInstance("DES"            Cipher.getInstance("AES/ECB"
new Random(                          Math.random(
```

### PHP Sinks by Vuln Class

SQLi:
```
mysqli_query(      $mysqli->query(    $pdo->query(
$pdo->exec(        pg_query(          pg_exec(
mysql_query(       mssql_query(
```

CMDi:
```
system(    exec(    shell_exec(    passthru(
popen(     proc_open(    pcntl_exec(
```

XSS:
```
echo    print    printf    header(
```

Path Traversal:
```
include(    include_once(    require(    require_once(
file_get_contents(    fopen(    readfile(
move_uploaded_file(
```

Deserialization:
```
unserialize(
```

XXE:
```
simplexml_load_string(    simplexml_load_file(
DOMDocument::loadXML(     DOMDocument::load(
xml_parse(                XMLReader::open(
```

LDAP Injection:
```
ldap_search(    ldap_list(    ldap_read(
ldap_add(       ldap_modify(  ldap_delete(
```

Weak Crypto (pattern-based, sources: []):
```
md5(    sha1(    rand(    mt_rand(
mcrypt_encrypt(MCRYPT_DES
```

### Go Sinks by Vuln Class

SQLi:
```
db.Query(      db.QueryRow(   db.Exec(
db.QueryContext(              tx.Query(
tx.QueryRow(   tx.Exec(       sqlx.Get(
sqlx.Select(   sqlx.Exec(
```

CMDi:
```
exec.Command(    exec.CommandContext(
```
NOTE: `exec.Command("sh", "-c", userInput)` is dangerous (shell invocation).
`exec.Command("ls", userDir)` is SAFE (arg array, no shell).
Flag only when first arg is "sh"/"bash"/"cmd" with user-controlled subsequent args,
OR when user input is the command itself.

XSS:
```
template.HTML(    template.JS(    template.URL(
template.CSS(     fmt.Fprintf(w,
```
NOTE: `html/template` package auto-escapes. `text/template` does NOT.
Flag usage of `text/template` with user data.

SSRF:
```
http.Get(    http.Post(    http.Head(
http.NewRequest(    client.Get(    client.Do(
```

Path Traversal:
```
os.Open(    os.Create(    os.ReadFile(
os.WriteFile(    ioutil.ReadFile(    ioutil.WriteFile(
http.ServeFile(    http.Dir(
```

LDAP Injection:
```
l.Search(    conn.Search(
```
Package: `github.com/go-ldap/ldap/v3`

Weak Crypto (pattern-based, sources: []):
```
md5.New(    sha1.New(    des.NewCipher(
rc4.NewCipher(    rand.Int(    rand.Float64(
```
NOTE: `math/rand` functions. NOT `crypto/rand` which is safe.

### C# Sinks by Vuln Class

SQLi:
```
new SqlCommand(       .ExecuteReader(      .ExecuteNonQuery(
.ExecuteScalar(       new NpgsqlCommand(   MySqlCommand(
.ExecuteSqlRaw(       .FromSqlRaw(
connection.Query(     connection.Execute(
```

CMDi:
```
Process.Start(    new ProcessStartInfo(    ProcessStartInfo(
```

XSS:
```
Response.Write(    Response.WriteAsync(
HttpContext.Response.WriteAsync(
@Html.Raw(         HtmlHelper.Raw(
```

Path Traversal:
```
File.ReadAllText(    File.WriteAllText(    File.Open(
File.Create(         new FileStream(       new StreamReader(
new StreamWriter(    Directory.GetFiles(
```

Deserialization:
```
BinaryFormatter.Deserialize(    XmlSerializer.Deserialize(
DataContractSerializer.ReadObject(    JsonConvert.DeserializeObject(
```

XXE:
```
new XmlDocument(    new XmlTextReader(
XDocument.Load(     XElement.Load(
XmlReader.Create(
```

SSRF:
```
new WebClient(.DownloadString(    WebRequest.Create(
HttpClient.GetAsync(              HttpClient.PostAsync(
HttpClient.SendAsync(
```

Weak Crypto (pattern-based, sources: []):
```
new MD5CryptoServiceProvider(    MD5.Create(
SHA1.Create(                      DES.Create(
new Random(                       RC2.Create(
```

### C Sinks by Vuln Class

Buffer Overflow:
```
strcpy(    strcat(    sprintf(    vsprintf(
gets(      memcpy(    memmove(    bcopy(
```

Format String:
```
printf(    fprintf(    sprintf(    snprintf(
vprintf(   vfprintf(   vsprintf(   syslog(
```

CMDi:
```
system(    popen(    execl(    execlp(
execle(    execv(    execvp(   execve(
```

### C++ Sinks by Vuln Class
(All C sinks apply plus:)
```
Buffer Overflow additional: std::string(user_ptr, user_len)
Deserialization: boost::archive::text_iarchive, cereal::JSONInputArchive
Format String: printf( family (std::cout << is NOT vulnerable)
```

---

## 10. SANITIZER REFERENCE BY VULN CLASS

Each sanitizer listed here neutralizes ONLY its specific vulnerability class.
Do not use SQLi sanitizers for XSS or vice versa.

```
SQLi sanitizers:
  Python:      %s placeholder, ? placeholder, :param placeholder, int(, float(
  JavaScript:  prepared statements, parameterized queries
  Java:        prepareStatement(, PreparedStatement, setString(, setInt(
  PHP:         prepare(, bindParam(, bindValue(, PDO::prepare
  Go:          ? placeholder in db.Query(, $1 in pgx
  C#:          SqlParameter(, cmd.Parameters.Add(, cmd.Parameters.AddWithValue(

CMDi sanitizers:
  Python:      shlex.quote(, pipes.quote(
  PHP:         escapeshellarg(, escapeshellcmd(
  All:         Use arg arrays instead of shell=True / string concat

XSS sanitizers:
  Python:      html.escape(, markupsafe.escape(, bleach.clean(
  JavaScript:  DOMPurify.sanitize(, he.encode(, validator.escape(
  Java:        ESAPI.encoder().encodeForHTML(, HtmlUtils.htmlEscape(, Encode.forHtml(
  PHP:         htmlspecialchars(, htmlentities(, strip_tags(
  Go:          template.HTMLEscapeString(, html/template package (auto-escapes)
  C#:          HttpUtility.HtmlEncode(, WebUtility.HtmlEncode(, HtmlEncoder.Default.Encode(

Path Traversal sanitizers:
  Python:      os.path.basename(, os.path.abspath(, pathlib.Path.resolve(
  JavaScript:  path.basename(, path.normalize(
  Java:        getCanonicalPath(, Path.normalize(
  PHP:         basename(, realpath(
  Go:          filepath.Base(, filepath.Clean(
  C#:          Path.GetFileName(, Path.GetFullPath(

XXE sanitizers:
  Java:        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
  PHP:         libxml_disable_entity_loader(true) (deprecated PHP 8.0 — now default)
  C#:          XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }
  Python:      defusedxml library (use instead of lxml/xml.etree for user-supplied XML)

Deserialization sanitizers:
  Python:      yaml.safe_load(, json.loads(, ast.literal_eval(
  PHP:         json_decode( (use instead of unserialize)
  Java:        No safe mode for ObjectInputStream — use allowlist validation
  C#:          JsonConvert.DeserializeObject<KnownType>( with explicit known type

LDAP Injection sanitizers:
  Python:      ldap3 with parameterized filters
  Go:          ldap.EscapeFilter(
  PHP:         ldap_escape(
  Java:        ESAPI.encoder().encodeForLDAP(

Weak Crypto sanitizers (safer alternatives):
  Python:      hashlib.sha256(, hashlib.sha512(, secrets.token_bytes(, os.urandom(
  JavaScript:  crypto.createHash('sha256', crypto.randomBytes(
  Java:        MessageDigest.getInstance("SHA-256", SecureRandom(
  PHP:         hash('sha256',, password_hash(, random_bytes(
  Go:          sha256.New(, sha512.New(, crypto/rand.Read(
  C#:          SHA256.Create(, RandomNumberGenerator.Create(
```

---

## 11. CONFIDENCE ASSIGNMENT RULES

These are strict. The validator enforces them.

**Always `Confirmed`:**
- SQLi, CMDi, XSS, SSRF, SSTI, XXE, Path Traversal, Open Redirect
- LDAP Injection, XPath Injection, Log Injection, Code Injection
- Deserialization, NoSQLi, Prototype Pollution
- Hardcoded Secret (pattern match on string literal)
- Weak Crypto (pattern match on insecure function call)
- JWT Bypass (pattern match on insecure decode call)

**Always `Tentative`:**
- All C/C++ memory rules: Buffer Overflow, Integer Overflow, Use After Free,
  Format String, Memory Corruption, Null Pointer Dereference, Race Condition
- CSRF (structural — detects absence of middleware)
- Cookie Security (structural — detects absence of flags)
- ReDoS (pattern on regex string — not taint-based)
- Race Condition in any language (CFG-based — needs runtime confirmation)
- Misconfiguration (structural — detects presence of insecure setting)
- Information Exposure (structural — detects debug/verbose output patterns)
- Cleartext Transmission (structural — detects HTTP vs HTTPS patterns)
- Missing security headers (absence detection)

**`Probable` (use sparingly):**
- When taint analysis can identify the general pattern but cannot confirm
  the exact flow — e.g., user input enters a class that is later serialized

---

## 12. EXPANSION ROADMAP — BATCH EXECUTION PLAN

After Phase 0 bug fixes, expand the ruleset in batches of exactly 30 rules per run.
Complete Phase 0 first. Then execute batches in order.

### Batch 1 — Fill Missing Vuln Classes: Python + JavaScript (30 rules)

Python missing coverage (9 rules):
```
python_file_upload           File Upload        CWE-434
python_mass_assignment       Mass Assignment    CWE-915
python_cors_misconfiguration Misconfiguration   CWE-942
python_insecure_temp_file    Path Traversal     CWE-377  (variant: tempfile.mktemp)
python_xpath_injection       XPath Injection    CWE-643  (if not already covered)
python_open_redirect_flask   Open Redirect      CWE-601  (variant: flask redirect)
python_log_injection_logging Log Injection      CWE-117  (variant: logging module)
python_sqli_django_orm       SQLi               CWE-89   (Django .raw() / .extra())
python_sqli_sqlalchemy       SQLi               CWE-89   (SQLAlchemy .text() / .raw())
```

JavaScript missing coverage (21 rules — pick 21 to fill the batch to 30):
```
js_xxe                       XXE                CWE-611
js_ldap_injection            LDAP Injection     CWE-90
js_hardcoded_secret          Hardcoded Secret   CWE-798
js_race_condition            Race Condition     CWE-362
js_cleartext_transmission    Cleartext Transmis CWE-319
js_info_exposure             Information Expose CWE-209
js_cors_misconfiguration     Misconfiguration   CWE-942
js_mass_assignment           Mass Assignment    CWE-915
js_file_upload               File Upload        CWE-434
js_misconfiguration_helmet   Misconfiguration   CWE-16
js_xss_innerhtml             XSS                CWE-79   (DOM XSS variant)
js_sqli_sequelize            SQLi               CWE-89   (Sequelize raw)
js_sqli_knex                 SQLi               CWE-89   (Knex raw/whereRaw)
js_nosqli_mongoose           NoSQLi             CWE-943  (Mongoose $where)
js_path_traversal_fs         Path Traversal     CWE-22   (fs.readFile variant)
js_cmdi_exec                 CMDi               CWE-78   (exec variant)
js_cmdi_spawn_shell          CMDi               CWE-78   (spawn shell:true)
js_proto_pollution_merge     Prototype Pollution CWE-1321
js_ssrf_axios                SSRF               CWE-918  (axios variant)
js_weak_crypto_md5           Weak Crypto        CWE-327  (crypto.createHash md5)
js_insecure_random           Weak Crypto        CWE-338  (Math.random)
```

### Batch 2 — Fill Missing Vuln Classes: Java + PHP (30 rules)

Java (7 rules):
```
java_nosqli                  NoSQLi             CWE-943
java_csrf                    CSRF               CWE-352
java_jwt_bypass              JWT Bypass         CWE-287
java_cookie_security         Cookie Security    CWE-614
java_redos                   ReDoS              CWE-1333
java_mass_assignment         Mass Assignment    CWE-915
java_cors_misconfiguration   Misconfiguration   CWE-942
```

PHP (11 rules):
```
php_nosqli                   NoSQLi             CWE-943
php_hardcoded_secret         Hardcoded Secret   CWE-798
php_csrf                     CSRF               CWE-352
php_jwt_bypass               JWT Bypass         CWE-287
php_cookie_security          Cookie Security    CWE-614
php_redos                    ReDoS              CWE-1333
php_cleartext_transmission   Cleartext Transmis CWE-319
php_info_exposure            Information Expose CWE-209
php_misconfiguration         Misconfiguration   CWE-16
php_cors_misconfiguration    Misconfiguration   CWE-942
php_xss_echo                 XSS                CWE-79   (echo variant)
```

Fill remaining to reach 30 with Java framework-specific rules:
```
java_sqli_hibernate          SQLi               CWE-89   (Hibernate HQL)
java_sqli_spring_jdbc        SQLi               CWE-89   (JdbcTemplate)
java_sqli_jpa_native         SQLi               CWE-89   (createNativeQuery)
java_sqli_mybatis            SQLi               CWE-89   (MyBatis ${})
java_deser_xstream           Deserialization    CWE-502  (XStream)
java_deser_snakeyaml         Deserialization    CWE-502  (SnakeYAML)
java_deser_jackson_poly      Deserialization    CWE-502  (Jackson enableDefaultTyping)
java_ssrf_resttemplate       SSRF               CWE-918  (RestTemplate)
java_ssrf_webclient          SSRF               CWE-918  (WebClient)
java_weak_crypto_ecb         Weak Crypto        CWE-327  (AES/ECB mode)
java_xss_jsp                 XSS                CWE-79   (JSP out.print)
java_cmdi_processbuilder     CMDi               CWE-78   (ProcessBuilder variant)
```

### Batch 3 — Fill Missing Vuln Classes: Go + C# + C + C++ (30 rules)

Go (11 rules):
```
go_nosqli                    NoSQLi             CWE-943  (research: MongoDB Go driver)
go_deserialization           Deserialization    CWE-502  (encoding/gob, encoding/json with interface{})
go_xpath_injection           XPath Injection    CWE-643  (research: antchfx/xpath)
go_code_injection            Code Injection     CWE-94   (plugin.Open with user path)
go_jwt_bypass                JWT Bypass         CWE-287  (golang-jwt/jwt alg=none)
go_cookie_security           Cookie Security    CWE-614  (http.SetCookie without Secure/HttpOnly)
go_redos                     ReDoS              CWE-1333 (regexp.MustCompile with user input)
go_race_condition            Race Condition     CWE-362  (Tentative)
go_info_exposure             Information Expose CWE-209  (log.Fatal/Printf of errors to HTTP)
go_cors_misconfiguration     Misconfiguration   CWE-942
go_sqli_sqlx                 SQLi               CWE-89   (sqlx library)
```

C# (8 rules):
```
csharp_nosqli                NoSQLi             CWE-943  (MongoDB C# driver)
csharp_hardcoded_secret      Hardcoded Secret   CWE-798
csharp_csrf                  CSRF               CWE-352
csharp_jwt_bypass            JWT Bypass         CWE-287
csharp_cookie_security       Cookie Security    CWE-614
csharp_redos                 ReDoS              CWE-1333
csharp_cors_misconfiguration Misconfiguration   CWE-942
csharp_sqli_dapper           SQLi               CWE-89   (Dapper library)
```

C (2 rules):
```
c_race_condition             Race Condition     CWE-362  (Tentative — TOCTOU)
c_null_pointer               Null Pointer Deref CWE-476  (Tentative)
```

C++ (6 rules):
```
cpp_use_after_free           Use After Free     CWE-416  (Tentative)
cpp_race_condition           Race Condition     CWE-362  (Tentative)
cpp_null_pointer             Null Pointer Deref CWE-476  (Tentative)
cpp_int_overflow_new         Integer Overflow   CWE-190  (new[] with user size)
cpp_bof_vector_unchecked     Buffer Overflow    CWE-122  (vector[] vs .at())
cpp_out_of_bounds_array      Out-of-bounds Read CWE-125  (array[user_index])
```

NOTE for Go XXE: Research whether `encoding/xml` processes external entities in
Go 1.21+. If not applicable, replace with `go_path_traversal_http` variant.
NOTE for Go Prototype Pollution: Go is strongly typed — this does not apply.
Do not write this rule. Replace with `go_sqli_pgx` (pgx library variant).

### Batches 4-10 — Deep Coverage (Framework-Specific + Variant Rules)

After Batches 1-3 complete, the missing class coverage will be filled.
Batches 4-10 go deeper: one rule per specific sink/framework within existing classes.

**Batch 4** — Python CMDi + SSRF + Deserialization + Path Traversal depth
**Batch 5** — JavaScript XSS + NoSQLi + SQLi + Prototype Pollution depth
**Batch 6** — Java SQLi + Deserialization + SSRF + Weak Crypto depth
**Batch 7** — PHP SQLi + CMDi + XSS + SSRF depth
**Batch 8** — Go + C# framework-specific SQLi + Path Traversal depth
**Batch 9** — C/C++ Buffer Overflow + Format String + Integer Overflow depth
**Batch 10** — Security Headers + Session Management + Config across all languages

---

## 13. THE VALIDATOR — RUN AFTER EVERY BATCH

This script is the gate. Run it after every batch. Fix ALL errors before reporting done.

```python
import yaml, sys
from pathlib import Path

REQUIRED_FIELDS = [
    "rule_id","language","vuln_class","severity","cwe","owasp",
    "cvss_score","cvss_vector","confidence","issue","message",
    "sources","sinks","sanitizers","remediation"
]

ALLOWED_CLASSES = {
    "SQLi","NoSQLi","CMDi","XSS","SSTI","SSRF","XXE",
    "Path Traversal","Open Redirect","Deserialization","Code Injection",
    "LDAP Injection","XPath Injection","Log Injection","Hardcoded Secret",
    "Weak Crypto","JWT Bypass","Prototype Pollution","Buffer Overflow",
    "Integer Overflow","Format String","Use After Free","Memory Corruption",
    "Race Condition","Null Pointer Dereference","ReDoS","CSRF",
    "Misconfiguration","Cookie Security","Mass Assignment","File Upload",
    "Out-of-bounds Read","Cleartext Transmission","Information Exposure","DoS"
}

FORBIDDEN_CLASSES = {
    "Type Confusion","Log Forging","Best Practice",
    "Injection","Security Issue","Vulnerability"
}

MUST_TENTATIVE_CLASSES = {
    "Buffer Overflow","Integer Overflow","Use After Free","Format String",
    "Memory Corruption","Null Pointer Dereference","Race Condition","CSRF",
    "Cookie Security","ReDoS","Misconfiguration","Information Exposure",
    "Cleartext Transmission"
}

FORBIDDEN_SINKS = [
    "deprecated_function_","DeprecatedMethod","vulnerableSink",
    "fake_","dummy_","placeholder_","_vuln","vuln_func",
    "test_sink_","example_sink","unsafe_func_"
]

USELESS_REMEDIATION = [
    "validate and sanitize all user input",
    "ensure proper input validation",
    "follow secure coding best practices",
    "follow secure coding practices"
]

errors, seen_ids, per_lang = [], {}, {}

for f in sorted(Path("rules").rglob("*.yaml")):
    lang = f.parent.name
    per_lang[lang] = per_lang.get(lang, 0) + 1
    try:
        raw = f.read_text(encoding="utf-8")
        rule = yaml.safe_load(raw)
    except Exception as e:
        errors.append(f"PARSE ERROR {f.name}: {e}"); continue
    if not rule:
        errors.append(f"EMPTY FILE: {f.name}"); continue

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"MISSING '{field}': {f.name}")
        elif rule[field] is None or str(rule[field]).strip() == "":
            errors.append(f"EMPTY '{field}': {f.name}")

    # Unique rule_id
    rid = str(rule.get("rule_id","")).strip()
    if rid in seen_ids:
        errors.append(f"DUPLICATE rule_id '{rid}': {f.name} + {seen_ids[rid]}")
    else:
        seen_ids[rid] = f.name

    # vuln_class validity
    vc = str(rule.get("vuln_class","")).strip()
    if vc in FORBIDDEN_CLASSES:
        errors.append(f"FORBIDDEN vuln_class '{vc}': {f.name}")
    elif vc not in ALLOWED_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f.name}")

    # Confidence check for classes that must be Tentative
    conf = str(rule.get("confidence","")).strip()
    if vc in MUST_TENTATIVE_CLASSES and conf == "Confirmed":
        errors.append(f"vuln_class '{vc}' cannot be Confirmed — use Tentative: {f.name}")

    # Fabricated sinks
    for sink in (rule.get("sinks",[]) or []):
        for fb in FORBIDDEN_SINKS:
            if fb.lower() in str(sink).lower():
                errors.append(f"FABRICATED SINK '{sink}': {f.name}")

    # Message length
    msg = str(rule.get("message","")).strip()
    if len(msg) < 80:
        errors.append(f"MESSAGE TOO SHORT ({len(msg)} chars, need 80+): {f.name}")

    # Remediation quality
    rem = str(rule.get("remediation","")).strip()
    for useless in USELESS_REMEDIATION:
        if useless in rem.lower():
            errors.append(f"USELESS REMEDIATION: {f.name}")
    if len(rem) < 100:
        errors.append(f"REMEDIATION TOO SHORT ({len(rem)} chars, need 100+): {f.name}")

    # Research evidence required
    if "# RESEARCH EVIDENCE" not in raw:
        errors.append(f"MISSING RESEARCH EVIDENCE COMMENT: {f.name}")

total = sum(per_lang.values())
print(f"Total rules: {total}")
print(f"Per language: {dict(sorted(per_lang.items()))}")
print(f"Unique rule IDs: {len(seen_ids)}")
print(f"Errors: {len(errors)}")
for e in errors:
    print(f"  ERROR: {e}")
if not errors:
    print("\nALL RULES PASS VALIDATION")
    sys.exit(0)
else:
    print(f"\nFIX ALL {len(errors)} ERRORS BEFORE PROCEEDING")
    sys.exit(1)
```

---

## 14. EXAMPLE OF A PERFECT RULE

Study this. Every rule you write must match this quality level.

```yaml
# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/90.html
# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/go/semmle/go/security/LdapInjection.qll
# Semgrep Source:  https://semgrep.dev/r/go.lang.security.ldap-injection
# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
# Verification:    l.Search() and conn.Search() are from github.com/go-ldap/ldap/v3,
#                  the most widely-used Go LDAP client. ldap.EscapeFilter() is its
#                  official sanitizer. Confirmed via pkg.go.dev documentation.

rule_id: go_ldap_injection
language: go
vuln_class: LDAP Injection
severity: High
cwe: CWE-90
owasp: A03:2021-Injection
cvss_score: 7.5
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
confidence: Confirmed
issue: "LDAP Injection via unsanitized user input in go-ldap Search filter"
message: |-
  User-controlled data from an HTTP request is passed directly into an LDAP
  search filter without escaping via ldap.EscapeFilter(). An attacker can
  inject LDAP metacharacters to manipulate the search query, bypass
  authentication, access unauthorized directory entries, or enumerate all
  LDAP objects in the directory.
sources:
  - r.URL.Query().Get(
  - r.FormValue(
  - r.PostFormValue(
  - r.Header.Get(
  - r.Cookie(
  - r.Body
  - c.Query(
  - c.DefaultQuery(
  - c.Param(
  - c.PostForm(
  - os.Getenv(
  - os.Args[
sinks:
  - l.Search(
  - conn.Search(
sanitizers:
  - ldap.EscapeFilter(
remediation: |-
  Escape all user-supplied input using ldap.EscapeFilter() from the
  github.com/go-ldap/ldap/v3 package before incorporating it into LDAP
  search filters. Never concatenate user input directly into filter strings.

  UNSAFE:
    filter := fmt.Sprintf("(cn=%s)", userInput)
    searchRequest := ldap.NewSearchRequest("dc=example,dc=com",
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        filter, []string{"dn"}, nil)

  SAFE:
    safeInput := ldap.EscapeFilter(userInput)
    filter := fmt.Sprintf("(cn=%s)", safeInput)
    searchRequest := ldap.NewSearchRequest(...)

  See OWASP LDAP Injection Prevention Cheat Sheet for complete guidance:
  https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
```

---

## 15. ABSOLUTE PROHIBITIONS

Breaking any of these causes validator failures or false detections in production.

**NEVER fabricate sinks.** If you cannot find a real URL for a function, omit it.
**NEVER use forbidden vuln_class values:** `Type Confusion`, `Log Forging`, `Best Practice`, `Injection`, `Security Issue`
**NEVER claim `confidence: Confirmed`** for memory rules, CSRF, Cookie Security, ReDoS, Race Condition, Misconfiguration, or any absence-detection rule.
**NEVER write `remediation: "Validate and sanitize all user input."`** — it is useless.
**NEVER put sanitizers in `sources:`** or sources in `sinks:`.
**NEVER put HTTP sources** in Weak Crypto, Hardcoded Secret, ReDoS, CSRF, or Cookie Security rules — they use `sources: []`.
**NEVER copy the same message text** from one rule to another — every message is unique to its sink.
**NEVER create a rule for a vulnerability that does not apply to the language** — e.g., Prototype Pollution in Go (strongly typed), XXE in Go's `encoding/xml` (does not process external entities by default in Go 1.20+).
**NEVER skip the research step.** Every sink in every rule needs a URL in the evidence comment.
**NEVER report a batch complete** without pasting the validator output showing 0 errors.

---

## 16. BATCH REPORTING FORMAT

After every batch, submit exactly this:

```
═══════════════════════════════════════════════
BATCH {N} COMPLETE
═══════════════════════════════════════════════
Rules written: {count}
New total:     {count}

New rules (one line per rule):
  {rule_id} | {vuln_class} | CWE-{N} | Primary sink: {function} | Source: {URL}
  ...

Rules NOT written (replace with alternate if needed):
  {reason why a planned rule was skipped}

Validator output:
─────────────────
Total rules: {N}
Per language: {dict}
Unique rule IDs: {N}
Errors: 0
ALL RULES PASS VALIDATION
─────────────────
═══════════════════════════════════════════════
```

Do not proceed to the next batch without this format.
Do not submit "I completed the batch" without the validator output.
```
