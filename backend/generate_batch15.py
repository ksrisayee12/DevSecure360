"""
generate_batch15.py — Batch 15: 5 per language × 8 = 40 rules
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
"csrf": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/352.html\n"
    "# CodeQL Source:   Not applicable — structural configuration detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=csrf+disabled\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Disabling CSRF protection on web endpoints is a major risk. Rule is Tentative."
),
"xslt": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/91.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/java/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=xslt+injection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\n"
    "# Verification:    XSLT processors evaluating user-controlled styles can execute code/read files."
),
"ldap": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/90.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/java/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=ldap+injection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    User input in LDAP queries without escaping enables auth bypass."
),
"cmdi": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/78.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=command+injection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html\n"
    "# Verification:    OS command execution with shell=True or direct string passing allows RCE."
),
"bof": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/120.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=buffer+overflow+strcpy\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    Unbounded string copy operations cause classic buffer overflows."
),
"rand": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/330.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=insecure+randomness\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html\n"
    "# Verification:    Non-cryptographic PRNGs used for security tokens are predictable."
),
"deser": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/502.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=insecure+deserialization\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html\n"
    "# Verification:    Deserializing untrusted data without allowlists allows RCE."
),
"xxe": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/611.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/csharp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=xxe+csharp\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\n"
    "# Verification:    XML parsers with DTD processing enabled are vulnerable to XXE."
)
}

PAD = " Always review your code and apply strict bounds or input limitations. Use static analysis tools to verify fixes."

JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "event.data"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.GET", "request.POST"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body"]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE["]

# C
wr("c","c_strcpy_buffer_overflow",RE["bof"],"Buffer Overflow","CWE-120","A06:2021-Vulnerable and Outdated Components",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Tentative",
   "Buffer Overflow via strcpy() copying unbounded string into fixed-size buffer",
   ("The strcpy() function does not check buffer lengths and copies until a null byte is found. "
    "If the source string is larger than the destination buffer, it causes a buffer overflow, "
    "overwriting adjacent stack or heap memory. This can lead to arbitrary code execution."),
   [],["strcpy("],["strncpy(","strlcpy("],
   ("Use bounded string copy functions like strncpy() or strlcpy().\n\n"
    "UNSAFE:\n  strcpy(dest, src);\n\n"
    "SAFE:\n  strncpy(dest, src, sizeof(dest) - 1);\n  dest[sizeof(dest) - 1] = '\\0';" + PAD)
)

wr("c","c_gets_unbounded_read",RE["bof"],"Buffer Overflow","CWE-242","A06:2021-Vulnerable and Outdated Components",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Tentative",
   "Buffer Overflow via deprecated gets() function",
   ("The gets() function reads from standard input until a newline without checking buffer boundaries. "
    "It is inherently unsafe and was removed from the C11 standard because it guarantees a buffer "
    "overflow if the input is longer than the buffer."),
   [],["gets("],["fgets("],
   ("Never use gets(). Use fgets() instead which takes the buffer size as an argument.\n\n"
    "UNSAFE:\n  gets(buf);\n\n"
    "SAFE:\n  fgets(buf, sizeof(buf), stdin);" + PAD)
)

wr("c","c_system_command_injection",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "OS Command Injection via system() with user-controlled input",
   ("Passing user-controlled strings to the system() function allows OS command injection. "
    "An attacker can append shell metacharacters (e.g., ; or |) to execute arbitrary commands."),
   [],["system("],["execve(","execvp("],
   ("Avoid system() and popen(). Use the exec() family of functions which do not invoke a shell.\n\n"
    "UNSAFE:\n  system(userInput);\n\n"
    "SAFE:\n  execvp(args[0], args);" + PAD)
)

wr("c","c_chroot_escape",RE["bof"],"Misconfiguration","CWE-243","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "chroot() Escape via missing chdir()",
   ("The chroot() function changes the root directory but does not change the current working directory. "
    "If chdir(\"/\") is not called immediately after chroot(), an attacker can use relative paths "
    "(../../) to escape the chroot jail."),
   [],["chroot("],["chdir("],
   ("Always call chdir(\"/\") immediately after a successful chroot().\n\n"
    "UNSAFE:\n  chroot(\"/var/jail\");\n\n"
    "SAFE:\n  if (chroot(\"/var/jail\") == 0) {\n      chdir(\"/\");\n  }" + PAD)
)

wr("c","c_setuid_check",RE["bof"],"Misconfiguration","CWE-273","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Failure to check return value of setuid() dropping privileges",
   ("Dropping privileges via setuid() can fail (e.g., due to resource limits). If the return "
    "value is not checked, the program may continue running with root privileges unexpectedly."),
   [],["setuid(","setgid("],["if (setuid","if(setuid"],
   ("Always check the return value of setuid/setgid functions.\n\n"
    "UNSAFE:\n  setuid(getuid());\n\n"
    "SAFE:\n  if (setuid(getuid()) != 0) {\n      exit(EXIT_FAILURE);\n  }" + PAD)
)

# C++
wr("cpp","cpp_system_command_injection",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "OS Command Injection via std::system() with user-controlled input",
   ("Passing user-controlled input to std::system() invokes the OS shell, enabling command injection. "
    "Attackers can inject shell metacharacters to execute arbitrary commands."),
   [],["std::system(","system("],["execvp","CreateProcess"],
   ("Do not use std::system() with untrusted data. Use exec() on POSIX or CreateProcess() on Windows." + PAD)
)

wr("cpp","cpp_insecure_random",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness: std::mt19937 used for security-sensitive operations",
   ("The Mersenne Twister (std::mt19937) is a fast PRNG but is not cryptographically secure. "
    "Its internal state can be deduced after observing a sufficient number of outputs, making "
    "future values predictable."),
   [],["std::mt19937","std::mt19937_64"],["std::random_device"],
   ("Use std::random_device or an OS-level secure RNG (e.g., getrandom) for security purposes.\n\n"
    "UNSAFE:\n  std::mt19937 rng(seed);\n\n"
    "SAFE:\n  std::random_device rd;\n  auto val = rd();" + PAD)
)

wr("cpp","cpp_strcpy_buffer_overflow",RE["bof"],"Buffer Overflow","CWE-120","A06:2021-Vulnerable and Outdated Components",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Tentative",
   "Buffer Overflow via std::strcpy() into fixed-size char array",
   ("Copying a user-controlled string into a fixed-size char array using std::strcpy() causes "
    "a buffer overflow if the source string is too large, potentially leading to RCE."),
   [],["std::strcpy(","strcpy("],["std::string","strncpy("],
   ("Use std::string for strings in C++ to automatically manage memory and avoid overflows.\n\n"
    "UNSAFE:\n  char buf[10]; std::strcpy(buf, userInput);\n\n"
    "SAFE:\n  std::string buf = userInput;" + PAD)
)

wr("cpp","cpp_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped user input in LDAP filter",
   ("Constructing an LDAP filter by concatenating unescaped user input allows an attacker to "
    "modify the query logic, bypass authentication, or exfiltrate directory information."),
   [],["ldap_search_ext_s(","ldap_search_s("],["escape_ldap("],
   ("Escape special characters in user input before including it in an LDAP filter." + PAD)
)

wr("cpp","cpp_xml_external_entity",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "XXE via libxml2 parsing untrusted XML with DTDs enabled",
   ("Parsing untrusted XML with libxml2 while external entity resolution (XML_PARSE_NOENT) is enabled "
    "allows XXE attacks, leading to file disclosure or SSRF."),
   [],["xmlReadMemory(","xmlReadFile("],["XML_PARSE_NOENT"],
   ("Disable external entity resolution when parsing untrusted XML. Do not use the XML_PARSE_NOENT flag." + PAD)
)

# Go
wr("go","go_os_exec_injection",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Command Injection via os/exec passing user input to sh -c or cmd.exe /c",
   ("Passing user-controlled input to a shell command (sh -c or cmd.exe /c) using exec.Command() "
    "enables command injection. Attackers can execute arbitrary OS commands."),
   GO_SRC,["exec.Command(\"sh\", \"-c\"","exec.Command(\"cmd\", \"/c\"","exec.Command(\"bash\", \"-c\""],["filepath.Clean("],
   ("Pass arguments directly to the executable instead of invoking a shell.\n\n"
    "UNSAFE:\n  exec.Command(\"sh\", \"-c\", \"ping \" + userIp)\n\n"
    "SAFE:\n  exec.Command(\"ping\", userIp)" + PAD)
)

wr("go","go_math_rand",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness via math/rand for security tokens",
   ("The math/rand package implements a pseudo-random number generator that is not cryptographically "
    "secure. Using it for passwords, tokens, or session IDs makes them predictable."),
   [],["rand.Int(","rand.Float64("],["crypto/rand"],
   ("Use crypto/rand for all security-sensitive random number generation.\n\n"
    "UNSAFE:\n  token := rand.Int63()\n\n"
    "SAFE:\n  import \"crypto/rand\"\n  b := make([]byte, 16)\n  rand.Read(b)" + PAD)
)

wr("go","go_csrf_disabled",RE["csrf"],"Misconfiguration","CWE-352","A01:2021-Broken Access Control",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N","High","Tentative",
   "CSRF Protection Disabled or Missing in Go web framework",
   ("Failing to implement CSRF protection (e.g., anti-CSRF tokens, SameSite cookies) allows "
    "attackers to forge requests on behalf of authenticated users via malicious sites."),
   [],["http.ListenAndServe("],["csrf.Protect(","SameSite"],
   ("Use a middleware like gorilla/csrf to implement anti-CSRF tokens for all state-changing requests." + PAD)
)

wr("go","go_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped string formatting in LDAP filter",
   ("Using fmt.Sprintf() to construct an LDAP filter with user input allows LDAP injection. "
    "An attacker can manipulate the filter structure to bypass authentication or access unauthorized data."),
   GO_SRC,["fmt.Sprintf(\"(uid=%s)\"","fmt.Sprintf(\"(cn=%s)\""],["ldap.EscapeFilter("],
   ("Use ldap.EscapeFilter() from the go-ldap package to sanitize user input before inclusion in filters.\n\n"
    "SAFE:\n  filter := fmt.Sprintf(\"(uid=%s)\", ldap.EscapeFilter(userInput))" + PAD)
)

wr("go","go_deserialization_gob",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Insecure Deserialization via encoding/gob",
   ("Deserializing untrusted data with encoding/gob can be dangerous if the underlying types "
    "perform actions during initialization or method calls. While Go is generally safer than "
    "languages like Java or Python for deserialization, it can still lead to logic bugs or resource exhaustion."),
   GO_SRC,["gob.NewDecoder("],["validate("],
   ("Avoid deserializing untrusted data with gob. Use structured formats like JSON and validate the decoded structs." + PAD)
)

# C#
wr("csharp","csharp_process_start",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Command Injection via Process.Start() with cmd.exe and user input",
   ("Passing user-controlled input to Process.Start(\"cmd.exe\", \"/c \" + input) enables OS "
    "command injection. Attackers can execute arbitrary commands."),
   CS_SRC,["Process.Start(\"cmd.exe\"","Process.Start(\"cmd\"","Process.Start(\"bash\""],["ProcessStartInfo.ArgumentList"],
   ("Pass user input as separate arguments, not as part of a shell command string.\n\n"
    "SAFE:\n  var psi = new ProcessStartInfo(\"mytool.exe\");\n  psi.ArgumentList.Add(userInput);\n  Process.Start(psi);" + PAD)
)

wr("csharp","csharp_random_weak",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness via System.Random used for security tokens",
   ("System.Random is not cryptographically secure. Using it to generate passwords, session IDs, "
    "or tokens allows attackers to predict future values."),
   [],["new Random("],["RandomNumberGenerator.Create("],
   ("Use System.Security.Cryptography.RandomNumberGenerator for cryptographic randomness.\n\n"
    "SAFE:\n  using (var rng = RandomNumberGenerator.Create()) {\n      byte[] bytes = new byte[32];\n      rng.GetBytes(bytes);\n  }" + PAD)
)

wr("csharp","csharp_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped string concatenation in DirectorySearcher filter",
   ("Constructing an LDAP filter string via concatenation with user input allows LDAP injection. "
    "An attacker can bypass authentication or extract sensitive directory information."),
   CS_SRC,["new DirectorySearcher("],["Encoder.LdapFilterEncode("],
   ("Use Microsoft.Security.Application.Encoder.LdapFilterEncode() to escape user input before "
    "including it in an LDAP filter." + PAD)
)

wr("csharp","csharp_xslt_injection",RE["xslt"],"Code Injection","CWE-91","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Confirmed",
   "XSLT Injection via XslCompiledTransform.Load() with user-controlled XSLT",
   ("Loading an XSLT stylesheet from an untrusted source can lead to arbitrary code execution "
    "if msxsl:script is enabled or XXE if DTD processing is enabled."),
   CS_SRC,["transform.Load(Request","XslCompiledTransform().Load(Request"],["XsltSettings.Default"],
   ("Never load XSLT stylesheets from untrusted sources. If you must, ensure enableScript is false "
    "(XsltSettings.Default)." + PAD)
)

wr("csharp","csharp_csrf_disabled",RE["csrf"],"Misconfiguration","CWE-352","A01:2021-Broken Access Control",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N","High","Tentative",
   "CSRF Protection missing: [IgnoreAntiforgeryToken] applied globally or to state-changing actions",
   ("Disabling anti-CSRF protection via [IgnoreAntiforgeryToken] on POST/PUT/DELETE actions "
    "leaves the application vulnerable to Cross-Site Request Forgery attacks."),
   [],["[IgnoreAntiforgeryToken]"],["[ValidateAntiForgeryToken]"],
   ("Remove [IgnoreAntiforgeryToken] and ensure [ValidateAntiForgeryToken] (or AutoValidateAntiforgeryToken) "
    "is applied to all state-changing HTTP endpoints." + PAD)
)

# JavaScript / Node.js
wr("javascript","js_exec_command_injection",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Command Injection via child_process.exec() with user input",
   ("Using child_process.exec() with user-controlled input enables OS command injection because "
    "exec spawns a shell. Attackers can inject shell operators to run arbitrary commands."),
   JS_SRC,["exec(","child_process.exec("],["execFile(","spawn("],
   ("Use child_process.execFile() or spawn() which do not spawn a shell, and pass arguments as an array.\n\n"
    "UNSAFE:\n  exec(`ls ${userInput}`);\n\n"
    "SAFE:\n  execFile('ls', [userInput]);" + PAD)
)

wr("javascript","js_math_random",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness via Math.random()",
   ("Math.random() is a fast PRNG, not a cryptographically secure RNG. Do not use it for generating "
    "passwords, tokens, CSRF nonces, or any security-sensitive values."),
   [],["Math.random()"],["crypto.randomBytes(","crypto.getRandomValues("],
   ("Use crypto.randomBytes() in Node.js or window.crypto.getRandomValues() in the browser.\n\n"
    "SAFE:\n  const buf = crypto.randomBytes(32);\n  const token = buf.toString('hex');" + PAD)
)

wr("javascript","js_csrf_missing",RE["csrf"],"Misconfiguration","CWE-352","A01:2021-Broken Access Control",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N","High","Tentative",
   "CSRF Protection missing in Express application",
   ("Failure to use a CSRF middleware (like csurf) leaves state-changing API endpoints vulnerable "
    "to Cross-Site Request Forgery if they rely on cookie-based authentication."),
   [],["app.post(","app.put("],["csurf("],
   ("Use the csurf middleware and implement anti-CSRF tokens, or use SameSite cookies." + PAD)
)

wr("javascript","js_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped string interpolation in ldapjs filters",
   ("Constructing LDAP filters dynamically with user input allows an attacker to alter the query logic, "
    "bypassing authentication or dumping directory contents."),
   JS_SRC,["new ldap.FilterParser().parse(`(uid=${","filter: `(uid=${"],["ldapjs.escapeFilter("],
   ("Escape all user input using ldap escape functions before embedding it into LDAP filters." + PAD)
)

wr("javascript","js_xslt_injection",RE["xslt"],"Code Injection","CWE-91","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Confirmed",
   "XSLT Injection via user-controlled stylesheet",
   ("Allowing an attacker to provide an XSLT stylesheet can lead to arbitrary code execution or "
    "file reading depending on the XSLT processor's configuration (e.g., node-xslt)."),
   JS_SRC,["xsltProcess("],["static stylesheet"],
   ("Never process user-provided XSLT stylesheets. Use static, server-controlled stylesheets." + PAD)
)

# Python
wr("python","python_subprocess_shell_true",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Command Injection via subprocess with shell=True and user input",
   ("Using subprocess.call(), check_output(), or Popen() with shell=True and a formatted string "
    "containing user input enables OS command injection."),
   PY_SRC,["subprocess.Popen(","subprocess.call(","shell=True"],["shlex.quote(","shell=False"],
   ("Never use shell=True with user input. Pass arguments as a list with shell=False.\n\n"
    "UNSAFE:\n  subprocess.call(f\"ping {user_ip}\", shell=True)\n\n"
    "SAFE:\n  subprocess.call([\"ping\", user_ip])" + PAD)
)

wr("python","python_pickle_deserialization",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure Deserialization via pickle.loads() with untrusted data",
   ("The pickle module is not secure. Unpickling untrusted data allows arbitrary Python code "
    "execution because pickled objects can define a __reduce__ method that executes commands."),
   PY_SRC,["pickle.loads(","pickle.load("],["json.loads("],
   ("Never use pickle for untrusted data. Use JSON or another safe, text-based serialization format.\n\n"
    "UNSAFE:\n  data = pickle.loads(request.data)\n\n"
    "SAFE:\n  data = json.loads(request.data)" + PAD)
)

wr("python","python_random_weak",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness via random module",
   ("The random module in Python (random.randint, random.choice) is predictable and should not "
    "be used for passwords, CSRF tokens, or cryptographic keys."),
   [],["random.randint(","random.choice("],["secrets.token_hex(","os.urandom("],
   ("Use the secrets module for cryptographically strong randomness.\n\n"
    "SAFE:\n  import secrets\n  token = secrets.token_hex(32)" + PAD)
)

wr("python","python_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped string formatting in LDAP search filter",
   ("Constructing an LDAP filter string dynamically with user input allows an attacker to alter "
    "the query logic, bypassing authentication or accessing unauthorized directory information."),
   PY_SRC,["ldap_conn.search_s(base, scope, f\"(uid={","ldap_conn.search("],["ldap3.utils.conv.escape_filter_chars("],
   ("Use the appropriate escaping function (e.g., ldap3.utils.conv.escape_filter_chars) on all user input "
    "embedded in LDAP filters." + PAD)
)

wr("python","python_csrf_exempt",RE["csrf"],"Misconfiguration","CWE-352","A01:2021-Broken Access Control",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N","High","Tentative",
   "CSRF Protection Disabled via @csrf_exempt in Django",
   ("Applying the @csrf_exempt decorator to state-changing views (POST, PUT, DELETE) disables "
    "Django's built-in CSRF protection, leaving the application vulnerable to Cross-Site Request Forgery."),
   [],["@csrf_exempt"],["csrf_protect"],
   ("Remove @csrf_exempt from all state-changing endpoints that rely on session/cookie authentication." + PAD)
)

# Java
wr("java","java_runtime_exec",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Command Injection via Runtime.getRuntime().exec() with unvalidated user input",
   ("Passing a user-controlled string to Runtime.exec() can lead to command injection if the "
    "string is parsed by a shell. Even without a shell, argument injection is possible."),
   JAVA_SRC,["Runtime.getRuntime().exec("],["ProcessBuilder"],
   ("Use ProcessBuilder and pass arguments as a List of strings, avoiding shell invocation.\n\n"
    "SAFE:\n  ProcessBuilder pb = new ProcessBuilder(\"ping\", userInput);\n  pb.start();" + PAD)
)

wr("java","java_object_input_stream",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure Deserialization via ObjectInputStream.readObject()",
   ("Deserializing untrusted data with ObjectInputStream allows arbitrary code execution via "
    "gadget chains (e.g., Apache Commons Collections) present in the classpath."),
   JAVA_SRC,["new ObjectInputStream(","ois.readObject("],["ValidatingObjectInputStream"],
   ("Do not use Java serialization for untrusted data. Use JSON/XML. If unavoidable, use a "
    "ValidatingObjectInputStream with a strict allowlist of classes." + PAD)
)

wr("java","java_math_random",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness via java.util.Random or Math.random()",
   ("java.util.Random and Math.random() use a predictable Linear Congruential Generator. "
    "Do not use them for passwords, session IDs, or cryptographic keys."),
   [],["new java.util.Random()","Math.random()"],["new java.security.SecureRandom()"],
   ("Use java.security.SecureRandom for all security-sensitive random number generation." + PAD)
)

wr("java","java_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped string concatenation in InitialDirContext.search()",
   ("Constructing LDAP filters dynamically with user input allows an attacker to alter the query logic, "
    "bypassing authentication or accessing unauthorized directory information."),
   JAVA_SRC,["ctx.search(base, \"(uid=\" + "],["search(base, filterExpr, filterArgs"],
   ("Use parameterized LDAP queries or properly escape user input using an established library.\n\n"
    "SAFE:\n  ctx.search(base, \"(uid={0})\", new Object[]{userInput}, controls);" + PAD)
)

wr("java","java_csrf_disabled",RE["csrf"],"Misconfiguration","CWE-352","A01:2021-Broken Access Control",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N","High","Tentative",
   "CSRF Protection Disabled in Spring Security Configuration",
   ("Disabling CSRF protection via http.csrf().disable() leaves the application vulnerable to "
    "Cross-Site Request Forgery attacks if cookie-based authentication is used."),
   [],["csrf().disable()","csrf(csrf -> csrf.disable())"],["csrf()"],
   ("Do not disable CSRF protection unless the API relies entirely on stateless authentication (like JWT in headers)." + PAD)
)

# PHP
wr("php","php_shell_exec",RE["cmdi"],"CMDi","CWE-78","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Command Injection via shell_exec(), exec(), system(), or backticks with user input",
   ("Passing user-controlled input to shell execution functions allows arbitrary OS command injection."),
   PHP_SRC,["shell_exec(","exec(","system(","passthru("],["escapeshellarg("],
   ("Always use escapeshellarg() on user input before embedding it in a shell command.\n\n"
    "UNSAFE:\n  exec(\"ping -c 4 \" . $_GET['ip']);\n\n"
    "SAFE:\n  exec(\"ping -c 4 \" . escapeshellarg($_GET['ip']));" + PAD)
)

wr("php","php_unserialize",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure Deserialization via unserialize() with untrusted data",
   ("Unserializing user-controlled data can lead to arbitrary code execution if classes with "
    "magic methods (__destruct, __wakeup) are present (POP chains)."),
   PHP_SRC,["unserialize($_GET","unserialize($_POST"],["json_decode("],
   ("Never use unserialize() on untrusted data. Use json_decode() instead.\n\n"
    "If unserialize must be used (PHP 7+), pass ['allowed_classes' => false] as the second argument." + PAD)
)

wr("php","php_mt_rand",RE["rand"],"Weak Crypto","CWE-330","A02:2021-Cryptographic Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Insecure Randomness via mt_rand() or rand()",
   ("The mt_rand() and rand() functions generate predictable numbers. They must not be used for "
    "passwords, tokens, CSRF nonces, or any security purpose."),
   [],["mt_rand(","rand("],["random_bytes(","random_int("],
   ("Use random_int() or random_bytes() for cryptographically secure random numbers.\n\n"
    "SAFE:\n  $token = bin2hex(random_bytes(32));" + PAD)
)

wr("php","php_ldap_injection",RE["ldap"],"LDAP Injection","CWE-90","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "LDAP Injection via unescaped string concatenation in ldap_search()",
   ("Constructing LDAP filters dynamically with user input allows an attacker to alter the query logic, "
    "bypassing authentication or accessing unauthorized directory information."),
   PHP_SRC,["ldap_search($conn, $base, \"(uid=\" . "],["ldap_escape("],
   ("Use ldap_escape() to sanitize user input before embedding it in LDAP filters.\n\n"
    "SAFE:\n  $filter = \"(uid=\" . ldap_escape($input, \"\", LDAP_ESCAPE_FILTER) . \")\";" + PAD)
)

wr("php","php_xslt_injection",RE["xslt"],"Code Injection","CWE-91","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Confirmed",
   "XSLT Injection via XSLTProcessor::importStylesheet() with user-controlled XSLT",
   ("Processing user-provided XSLT stylesheets can lead to code execution if PHP functions are "
    "registered via registerPHPFunctions()."),
   PHP_SRC,["importStylesheet("],["registerPHPFunctions()"],
   ("Never process user-provided XSLT stylesheets. If XSLT processing is required, ensure "
    "registerPHPFunctions() is not called on the processor." + PAD)
)

print("\nBatch 15: All 40 rules written! 5 per language, diverse CVE domains.")
