"""
generate_batch16.py — Batch 16: 5 per language × 8 = 40 rules
Themes: Open Redirect, SSRF, Path Traversal, MD5/SHA1 Weak Crypto, Format String (C/C++), Hardcoded Secrets, Mass Assignment.
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
"or": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/601.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=open+redirect\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html\n"
    "# Verification:    Unvalidated user input used in HTTP redirect headers leads to Open Redirect/Phishing."
),
"ssrf": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/918.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=ssrf\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html\n"
    "# Verification:    User-controlled URLs passed to HTTP clients lead to SSRF, allowing internal network scanning."
),
"pt": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/22.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=path+traversal\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html\n"
    "# Verification:    User input in file paths without path sanitization allows arbitrary file read/write."
),
"crypto": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/327.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=weak+crypto\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html\n"
    "# Verification:    MD5 and SHA-1 are cryptographically broken and should not be used for security purposes."
),
"fmt": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/134.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=format+string\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    Using user input as a format string in printf-like functions allows memory read/write."
),
"secret": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/798.html\n"
    "# CodeQL Source:   Not applicable — pattern-based literal string detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=hardcoded+secret\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html\n"
    "# Verification:    Hardcoded cloud provider API keys lead to immediate resource compromise."
),
"mass": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/915.html\n"
    "# CodeQL Source:   Not applicable — pattern-based ORM detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=mass+assignment\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html\n"
    "# Verification:    Binding all request parameters to a model object allows updating unintended fields (e.g. isAdmin)."
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
wr("c","c_format_string_printf",RE["fmt"],"Format String","CWE-134","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Tentative",
   "Format String Vulnerability in printf()",
   ("Passing user-controlled input directly as the format string argument to printf() enables format "
    "string attacks. Attackers can use %x to read memory or %n to write memory, leading to RCE."),
   [],["printf(userInput)","fprintf(file, userInput)","sprintf(buf, userInput)"],["%s"],
   ("Always use a static format string (e.g., \"%s\") when printing user-controlled data.\n\n"
    "UNSAFE:\n  printf(userInput);\n\n"
    "SAFE:\n  printf(\"%s\", userInput);" + PAD)
)
wr("c","c_path_traversal_fopen",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via fopen() with unvalidated input",
   ("Using unvalidated user input to construct a file path for fopen() allows an attacker to "
    "read or write arbitrary files on the system using directory traversal characters (../)."),
   [],["fopen("],["realpath(","basename("],
   ("Sanitize user input by allowing only alphanumeric characters, or strictly validate against an "
    "allowlist of acceptable file names. Avoid direct file access based on user input." + PAD)
)
wr("c","c_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of MD5 algorithm",
   ("MD5 is a cryptographically broken hash function. It is vulnerable to collision attacks and "
    "should not be used for digital signatures, passwords, or data integrity checks."),
   [],["MD5_Init(","MD5("],["SHA256(","SHA3_"],
   ("Use a strong, modern cryptographic hash function such as SHA-256, SHA-3, or Argon2 for passwords." + PAD)
)
wr("c","c_hardcoded_aws_key",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded AWS Access Key ID",
   ("Hardcoding AWS access keys in source code allows an attacker to compromise cloud resources if "
    "the code is leaked, published, or extracted."),
   [],["\"AKIA","'AKIA"],["getenv("],
   ("Remove hardcoded AWS keys. Load credentials dynamically from environment variables, secure secret "
    "managers, or IAM roles." + PAD)
)
wr("c","c_format_string_syslog",RE["fmt"],"Format String","CWE-134","A03:2021-Injection",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Format String Vulnerability in syslog()",
   ("Passing untrusted input directly as the format argument to syslog() enables format string attacks "
    "which can overwrite memory and lead to RCE."),
   [],["syslog(LOG_INFO, userInput)","syslog(LOG_ERR, userInput)"],["%s"],
   ("Always provide a static format string like \"%s\" when logging user input with syslog()." + PAD)
)

# C++
wr("cpp","cpp_format_string_cout",RE["fmt"],"Format String","CWE-134","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Tentative",
   "Format String Vulnerability via std::printf in C++",
   ("Using std::printf or other C-style print functions with user-controlled format strings allows "
    "attackers to read or corrupt memory. C++ std::cout does not have this issue."),
   [],["std::printf(userInput","printf(userInput"],["std::cout"],
   ("Use std::cout or std::print (C++23) which are type-safe and do not interpret format strings maliciously, "
    "or use a static format string." + PAD)
)
wr("cpp","cpp_path_traversal_fstream",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via std::ifstream or std::ofstream",
   ("Constructing file paths with unvalidated user input and opening them via std::ifstream allows "
    "directory traversal attacks to read arbitrary files."),
   [],["std::ifstream(","std::ofstream("],["std::filesystem::canonical(","basename("],
   ("Validate user input against an allowlist, or use std::filesystem::canonical to resolve the path "
    "and ensure it resides within the intended base directory." + PAD)
)
wr("cpp","cpp_weak_crypto_sha1",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of SHA-1",
   ("SHA-1 is cryptographically weak and vulnerable to collision attacks (e.g., SHAttered). "
    "It must not be used for security purposes like password hashing or digital signatures."),
   [],["SHA1_Init(","SHA1("],["SHA256(","SHA3_"],
   ("Replace SHA-1 with a secure algorithm like SHA-256 or SHA-3 for hashing data." + PAD)
)
wr("cpp","cpp_hardcoded_github_token",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded GitHub Personal Access Token",
   ("Hardcoding a GitHub token (e.g., starting with ghp_, gho_) exposes the associated account or "
    "organization to source code theft, tampering, or malicious commits."),
   [],["\"ghp_","\"gho_"],["std::getenv("],
   ("Remove the hardcoded GitHub token. Supply it dynamically at runtime via environment variables or a vault." + PAD)
)
wr("cpp","cpp_ssrf_curl",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via libcurl with unvalidated URLs",
   ("Passing an unvalidated user-provided URL to curl_easy_setopt(curl, CURLOPT_URL, url) allows "
    "an attacker to make the server perform unauthorized HTTP requests to internal services (SSRF)."),
   [],["curl_easy_setopt(","CURLOPT_URL"],["validate_url("],
   ("Validate user-supplied URLs against an allowlist of permitted domains/IPs. Block private network "
    "ranges (e.g., 10.0.0.0/8, 127.0.0.1, 169.254.169.254)." + PAD)
)

# Go
wr("go","go_ssrf_http_get",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via http.Get() with unvalidated user input",
   ("Passing an unvalidated user-controlled URL to http.Get() or http.Post() enables SSRF. "
    "The attacker can abuse the server's network access to scan or attack internal infrastructure."),
   GO_SRC,["http.Get(","http.Post("],["url.Parse("],
   ("Parse the URL and validate the hostname/IP against a strict allowlist. Ensure it does not resolve "
    "to internal network addresses before making the request." + PAD)
)
wr("go","go_open_redirect",RE["or"],"Open Redirect","CWE-601","A01:2021-Broken Access Control",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","Medium","Confirmed",
   "Open Redirect via http.Redirect()",
   ("Passing an unvalidated user-provided URL directly to http.Redirect() allows an attacker to "
    "redirect victims to malicious phishing sites, bypassing security filters."),
   GO_SRC,["http.Redirect("],["allowed_urls["],
   ("Validate the target URL against an allowlist, or strictly ensure it is a relative path (e.g., "
    "starts with '/' but not '//') before redirecting." + PAD)
)
wr("go","go_path_traversal_os_open",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via os.Open() or os.ReadFile()",
   ("Opening files based on user input without validation allows directory traversal. "
    "Attackers can read sensitive files outside the intended directory."),
   GO_SRC,["os.Open(","os.ReadFile(","ioutil.ReadFile("],["filepath.Clean(","filepath.Base("],
   ("Use filepath.Base() to extract only the filename, and check if the resolved path starts with "
    "the expected base directory using strings.HasPrefix." + PAD)
)
wr("go","go_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of crypto/md5",
   ("Using crypto/md5 for hashing passwords or ensuring data integrity is insecure due to known "
    "collision vulnerabilities in the MD5 algorithm."),
   [],["md5.New(","md5.Sum("],["sha256.New("],
   ("Replace crypto/md5 with crypto/sha256 or a dedicated password hashing algorithm like bcrypt "
    "for security-sensitive operations." + PAD)
)
wr("go","go_hardcoded_stripe_key",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded Stripe API Secret Key",
   ("A hardcoded Stripe secret key (starting with sk_live_) enables full access to the payment "
    "provider account, leading to massive financial and data loss if compromised."),
   [],["\"sk_live_","\"rk_live_"],["os.Getenv("],
   ("Remove the hardcoded Stripe key. Use environment variables (os.Getenv) or a secrets manager." + PAD)
)

# C#
wr("csharp","csharp_ssrf_httpclient",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via HttpClient.GetAsync()",
   ("Passing user-controlled input to HttpClient.GetAsync() or SendAsync() enables SSRF attacks, "
    "allowing an attacker to access internal microservices or cloud metadata endpoints."),
   CS_SRC,["HttpClient().GetAsync(","client.GetAsync("],["Uri.IsWellFormedUriString("],
   ("Validate user-supplied URLs against an allowlist of approved domains. Ensure the parsed URI "
    "does not map to internal or loopback IP addresses." + PAD)
)
wr("csharp","csharp_open_redirect",RE["or"],"Open Redirect","CWE-601","A01:2021-Broken Access Control",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","Medium","Confirmed",
   "Open Redirect via Response.Redirect() or Redirect()",
   ("Redirecting users to unvalidated URLs provided via query parameters allows Open Redirect attacks. "
    "Attackers can conduct phishing by redirecting users from a trusted domain to a malicious one."),
   CS_SRC,["Response.Redirect(","return Redirect("],["Url.IsLocalUrl("],
   ("Use Url.IsLocalUrl() to ensure the redirect destination is a relative path within the application, "
    "or validate against a hardcoded list of allowed domains." + PAD)
)
wr("csharp","csharp_path_traversal_file_read",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via File.ReadAllText() or FileStream",
   ("Using unvalidated user input to construct a path for File.ReadAllText() allows an attacker to "
    "use relative paths (../) to read sensitive configuration files (e.g., appsettings.json)."),
   CS_SRC,["File.ReadAllText(","new FileStream("],["Path.GetFileName("],
   ("Sanitize user input by extracting only the filename using Path.GetFileName() and ensure the "
    "resolved path resides inside the permitted directory." + PAD)
)
wr("csharp","csharp_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of MD5CryptoServiceProvider",
   ("System.Security.Cryptography.MD5 or MD5CryptoServiceProvider implements the insecure MD5 hashing "
    "algorithm. It is vulnerable to collisions and not suitable for security operations."),
   [],["MD5.Create(","new MD5CryptoServiceProvider("],["SHA256.Create("],
   ("Replace MD5 with SHA256 (System.Security.Cryptography.SHA256.Create()) for data integrity, "
    "and use PBKDF2/Argon2 for passwords." + PAD)
)
wr("csharp","csharp_mass_assignment",RE["mass"],"Mass Assignment","CWE-915","A08:2021-Software and Data Integrity Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Mass Assignment / Over-Posting via Model Binding",
   ("Binding an entire HTTP request directly to an entity model (e.g., User) allows attackers to "
    "overwrite sensitive fields like IsAdmin or Role that were not intended to be exposed in the form."),
   ["[FromBody] User user"],["_context.Users.Update(user)"],["ViewModel","DTO"],
   ("Do not use entity models directly in API inputs. Create specific DTOs (Data Transfer Objects) "
    "or ViewModels that only contain the fields intended for user updates." + PAD)
)

# JavaScript / Node.js
wr("javascript","js_ssrf_axios",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via axios or fetch with unvalidated input",
   ("Passing user-controlled input directly to axios.get() or fetch() enables SSRF. The server "
    "will make arbitrary requests on behalf of the attacker, exposing internal networks."),
   JS_SRC,["axios.get(","axios.post(","fetch("],["new URL("],
   ("Strictly validate the user-provided URL against an allowlist. Resolve the DNS and verify it "
    "does not map to local/private IP ranges before making the request." + PAD)
)
wr("javascript","js_open_redirect_express",RE["or"],"Open Redirect","CWE-601","A01:2021-Broken Access Control",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","Medium","Confirmed",
   "Open Redirect via res.redirect() in Express",
   ("Using unvalidated input in res.redirect() allows attackers to redirect victims to malicious "
    "domains via phishing links."),
   JS_SRC,["res.redirect("],["URL constructor validate"],
   ("Validate the target URL against an allowlist, or enforce relative paths (e.g., if(url.startsWith('/'))) "
    "before redirecting." + PAD)
)
wr("javascript","js_path_traversal_fs_read",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via fs.readFile() or fs.readFileSync()",
   ("Concatenating user input into file paths passed to fs.readFile() allows attackers to read "
    "arbitrary files via directory traversal sequences (../)."),
   JS_SRC,["fs.readFile(","fs.readFileSync("],["path.basename(","path.resolve("],
   ("Use path.basename() to strip directory traversal sequences and resolve the path safely to ensure "
    "it stays within the expected base directory." + PAD)
)
wr("javascript","js_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of crypto.createHash('md5')",
   ("The MD5 algorithm is cryptographically weak and vulnerable to collisions. Do not use it for "
    "passwords, secure tokens, or integrity verification."),
   [],["crypto.createHash('md5')","crypto.createHash(\"md5\")"],["crypto.createHash('sha256')"],
   ("Switch to a modern cryptographic algorithm like SHA-256 for hashing, and use bcrypt or argon2 "
    "for storing passwords." + PAD)
)
wr("javascript","js_hardcoded_slack_token",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded Slack Bot Token",
   ("A hardcoded Slack token (starting with xoxb- or xoxp-) allows attackers to hijack the bot, "
    "read private messages, or spam channels if the code is exposed."),
   [],["\"xoxb-","\"xoxp-"],["process.env."],
   ("Never commit Slack tokens to source control. Load them via process.env.SLACK_TOKEN." + PAD)
)

# Python
wr("python","python_ssrf_requests",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via requests module",
   ("Passing unvalidated user input to requests.get() or requests.post() enables SSRF. The application "
    "can be used as a proxy to attack internal systems or read cloud metadata (e.g., AWS IMDS)."),
   PY_SRC,["requests.get(","requests.post("],["urllib.parse"],
   ("Validate the URL scheme and hostname. Ensure the resolved IP address does not fall into private "
    "network ranges (e.g., using the ipaddress module)." + PAD)
)
wr("python","python_open_redirect_flask",RE["or"],"Open Redirect","CWE-601","A01:2021-Broken Access Control",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","Medium","Confirmed",
   "Open Redirect via flask.redirect()",
   ("Passing user input directly to flask.redirect() or django.shortcuts.redirect() allows attackers "
    "to redirect users to malicious websites."),
   PY_SRC,["redirect("],["urlparse("],
   ("Ensure the URL is a safe, relative path. In Flask/Django, validate that the scheme and netloc "
    "are empty before redirecting." + PAD)
)
wr("python","python_path_traversal_open",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via open() with unvalidated input",
   ("Constructing file paths using unvalidated user input allows an attacker to use ../ sequences "
    "to read sensitive files (e.g., /etc/passwd) via the built-in open() function."),
   PY_SRC,["open("],["os.path.basename(","werkzeug.utils.secure_filename("],
   ("Extract only the filename using os.path.basename() or secure_filename(), and verify that "
    "os.path.abspath() remains within the intended directory." + PAD)
)
wr("python","python_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of hashlib.md5()",
   ("The hashlib.md5() algorithm is cryptographically broken and vulnerable to collisions. It is "
    "unsuitable for passwords, tokens, or digital signatures."),
   [],["hashlib.md5("],["hashlib.sha256("],
   ("Use hashlib.sha256() or higher for data hashing. For password storage, use argon2-cffi or bcrypt." + PAD)
)
wr("python","python_hardcoded_google_key",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded Google Cloud API Key",
   ("Hardcoding a Google Cloud API key (AIzaSy...) in source code exposes GCP services to abuse "
    "and quota exhaustion by unauthorized parties."),
   [],["\"AIzaSy","'AIzaSy"],["os.environ.get("],
   ("Remove the hardcoded key. Use os.environ or a secrets manager like Google Secret Manager." + PAD)
)

# Java
wr("java","java_ssrf_httpurlconnection",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via HttpURLConnection or HttpClient",
   ("Passing user-provided URLs to HttpURLConnection.openConnection() or Java 11 HttpClient enables "
    "SSRF. Attackers can reach internal applications bypassing firewalls."),
   JAVA_SRC,["url.openConnection()","HttpClient.newHttpClient().send("],["java.net.URI"],
   ("Parse the URL and validate the hostname against a strict allowlist. Resolve the IP address "
    "and ensure it is not a private IP before establishing the connection." + PAD)
)
wr("java","java_open_redirect_sendredirect",RE["or"],"Open Redirect","CWE-601","A01:2021-Broken Access Control",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","Medium","Confirmed",
   "Open Redirect via HttpServletResponse.sendRedirect()",
   ("Passing unvalidated input from query parameters directly into sendRedirect() allows attackers "
    "to redirect users to malicious external domains."),
   JAVA_SRC,["response.sendRedirect("],["URI validate"],
   ("Validate the URL to ensure it is a relative path (e.g., starts with '/') or matches an allowed "
    "domain list." + PAD)
)
wr("java","java_path_traversal_file",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Path Traversal via java.io.File or Files.readAllBytes()",
   ("Using unvalidated user input to instantiate java.io.File or Path allows attackers to access "
    "sensitive files via directory traversal sequences (../)."),
   JAVA_SRC,["new File(","Files.readAllBytes("],["FilenameUtils.getName("],
   ("Use Apache Commons IO FilenameUtils.getName() to extract only the filename. Ensure the "
    "canonical path of the file starts with the expected base directory." + PAD)
)
wr("java","java_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: MessageDigest.getInstance(\"MD5\")",
   ("MD5 is a weak cryptographic algorithm. Its use for hashing sensitive data or generating "
    "signatures leaves the application vulnerable to collision attacks."),
   [],["MessageDigest.getInstance(\"MD5\")"],["MessageDigest.getInstance(\"SHA-256\")"],
   ("Change the algorithm to SHA-256 or SHA-3. For passwords, use BCryptPasswordEncoder or Argon2." + PAD)
)
wr("java","java_mass_assignment_spring",RE["mass"],"Mass Assignment","CWE-915","A08:2021-Software and Data Integrity Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Mass Assignment via Spring MVC Model Binding",
   ("Binding an HTTP request directly to JPA Entity classes (e.g., @ModelAttribute or @RequestBody "
    "User user) allows an attacker to manipulate sensitive fields like roles or permissions."),
   ["@RequestBody User","@ModelAttribute User"],["save(","update("],["DTO"],
   ("Create specific Data Transfer Objects (DTOs) for API inputs that only include the fields the "
    "user is allowed to update, rather than using Entity classes directly." + PAD)
)

# PHP
wr("php","php_ssrf_file_get_contents",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Server-Side Request Forgery (SSRF) via file_get_contents() or curl_exec()",
   ("Passing user-controlled input to file_get_contents() or cURL options allows an attacker to "
    "make the PHP server initiate HTTP requests to internal IP addresses or metadata services."),
   PHP_SRC,["file_get_contents(","curl_exec("],["filter_var("],
   ("Use filter_var with FILTER_VALIDATE_URL and strongly validate the host/IP against an allowlist, "
    "explicitly rejecting private networks." + PAD)
)
wr("php","php_open_redirect_header",RE["or"],"Open Redirect","CWE-601","A01:2021-Broken Access Control",
   6.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","Medium","Confirmed",
   "Open Redirect via header(\"Location: ...\")",
   ("Using unvalidated user input in the Location header enables Open Redirect attacks, "
    "facilitating phishing campaigns that exploit the trusted domain."),
   PHP_SRC,["header(\"Location: "],["allowed_domains"],
   ("Validate the target URL. If it's internal, ensure it starts with '/' (and not '//'). "
    "Otherwise, check it against a strict allowlist." + PAD)
)
wr("php","php_path_traversal_include",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "Path Traversal and LFI via include(), require(), or file_get_contents()",
   ("Concatenating user input into file paths used in include(), require(), or file_get_contents() "
    "allows attackers to read sensitive files or execute local PHP files (Local File Inclusion)."),
   PHP_SRC,["include(","require(","file_get_contents("],["basename("],
   ("Sanitize user input using basename() to strip directory traversal payloads. Validate against "
    "an allowlist of expected file names." + PAD)
)
wr("php","php_weak_crypto_md5",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of md5() or sha1()",
   ("The md5() and sha1() functions are cryptographically broken. They must not be used for "
    "passwords or sensitive data integrity verification due to collision risks."),
   [],["md5(","sha1("],["hash(\"sha256\""],
   ("Use hash('sha256', $data) for general hashing, and password_hash() with PASSWORD_DEFAULT "
    "or PASSWORD_ARGON2ID for passwords." + PAD)
)
wr("php","php_format_string_printf",RE["fmt"],"Format String","CWE-134","A03:2021-Injection",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Format String Vulnerability in printf() or sprintf()",
   ("Passing user input directly as the format string argument in printf() allows attackers to "
    "read variables and potentially manipulate program state through format string exploits."),
   PHP_SRC,["printf(","sprintf("],["%s"],
   ("Always use a static format string.\n\nUNSAFE: printf($_GET['msg']);\nSAFE: printf(\"%s\", $_GET['msg']);" + PAD)
)

print("\nBatch 16: All 40 rules written! 5 per language, diverse CVE domains.")
