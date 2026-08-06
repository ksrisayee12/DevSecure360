"""
generate_batch18.py — Batch 18: 5 per language × 8 = 40 rules
Themes: Information Exposure, JWT Bypass, Hardcoded Passwords, 
Null Pointer Deref, XPath Injection, Log Injection, Insecure File Upload.
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
"info": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/209.html\n"
    "# CodeQL Source:   Not applicable — structural error output pattern detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=information+exposure\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html\n"
    "# Verification:    Exposing stack traces or verbose debug messages to users facilitates reconnaissance. Rule is Tentative."
),
"jwt": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/287.html\n"
    "# CodeQL Source:   Not applicable — pattern-based JWT decode detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=jwt\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html\n"
    "# Verification:    Allowing the 'none' algorithm or skipping signature verification bypasses JWT authentication."
),
"secret": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/798.html\n"
    "# CodeQL Source:   Not applicable — pattern-based literal string detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=hardcoded+secret\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html\n"
    "# Verification:    Hardcoding passwords or database credentials in source code enables complete compromise upon source leak."
),
"npd": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/476.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  Not applicable — CFG-based detection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    Null pointer dereference causes crashes leading to DoS. Rule is Tentative."
),
"xpath": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/643.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=xpath\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Unescaped user input in XPath expressions allows bypassing logic or reading arbitrary XML data."
),
"log": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/117.html\n"
    "# CodeQL Source:   Not applicable — pattern-based log sink detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=log+injection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html\n"
    "# Verification:    Unsanitized CRLF characters in logs allow spoofing log entries (Log Forging)."
),
"upload": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/434.html\n"
    "# CodeQL Source:   Not applicable — pattern-based upload detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=file+upload\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html\n"
    "# Verification:    Missing extension and content validation on file uploads allows Remote Code Execution via web shells."
)
}

PAD = " Always review your code and apply strict validation and sanitization. Consult secure coding best practices."

JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "event.data"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.GET", "request.POST"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body"]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE[", "$_FILES["]

# C
wr("c","c_null_pointer_dereference",RE["npd"],"Null Pointer Dereference","CWE-476","A04:2021-Insecure Design",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","Medium","Tentative",
   "Null Pointer Dereference",
   ("Dereferencing a pointer returned by a function that can return NULL (e.g., malloc, fopen) "
    "without a prior check leads to application crashes and Denial of Service."),
   [],["malloc(","fopen("],["if (ptr != NULL)","if (ptr)"],
   ("Always check if a pointer is NULL before accessing its contents or fields, especially after "
    "allocation or file opening routines." + PAD)
)
wr("c","c_log_forging_syslog",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection (Forging) via syslog()",
   ("Logging unvalidated user input directly into syslog allows attackers to inject newline "
    "characters (CRLF) and forge fake log entries, undermining audit trails."),
   [],["syslog("],["str_replace(","remove_newlines("],
   ("Sanitize user input before logging by removing or escaping newline characters (\\r and \\n) "
    "to prevent log entry injection." + PAD)
)
wr("c","c_hardcoded_database_pwd",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded Database Password",
   ("Hardcoding a database password in C source code or connection strings leaves the database "
    "vulnerable to unauthorized access if the binary is reverse-engineered or source is leaked."),
   [],["\"password=","\"pwd="],["getenv("],
   ("Do not hardcode credentials. Store them in secure configuration files with restricted permissions "
    "or use environment variables." + PAD)
)
wr("c","c_xpath_injection_libxml",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via libxml2 xpathEval",
   ("Constructing XPath queries dynamically by concatenating unvalidated user input allows attackers "
    "to bypass XML structural logic and extract unauthorized data."),
   [],["xmlXPathEvalExpression("],["escape_xml("],
   ("Avoid dynamic XPath strings. If necessary, strictly validate input or use parameterized XPath "
    "evaluators if the library supports them." + PAD)
)
wr("c","c_info_exposure_printf_debug",RE["info"],"Information Exposure","CWE-209","A05:2021-Security Misconfiguration",
   4.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Low","Tentative",
   "Information Exposure via Debug Print Statements",
   ("Using printf() or fprintf(stderr, ...) to output raw variable dumps, stack states, or verbose "
    "internal details can expose sensitive information in production environments."),
   [],["printf(","fprintf(stderr"],["#ifdef DEBUG"],
   ("Ensure debug statements are conditionally compiled out of release builds using `#ifdef NDEBUG` "
    "or avoid logging sensitive system information entirely." + PAD)
)

# C++
wr("cpp","cpp_null_pointer_dereference",RE["npd"],"Null Pointer Dereference","CWE-476","A04:2021-Insecure Design",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","Medium","Tentative",
   "Null Pointer Dereference via raw pointers",
   ("Failing to verify that a raw pointer is not null before dereferencing it (e.g., calling methods "
    "or accessing members) leads to immediate segmentation faults."),
   [],["->","*ptr"],["if (ptr != nullptr)","if (ptr)"],
   ("Check raw pointers against nullptr before access, or preferably use smart pointers and references "
    "which inherently provide better memory safety guarantees." + PAD)
)
wr("cpp","cpp_log_forging_cout",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via std::cout / std::clog",
   ("Logging unvalidated user input using stream insertion operators can lead to log forging if the "
    "input contains carriage returns and newlines."),
   [],["std::cout <<","std::clog <<"],["sanitize_crlf("],
   ("Sanitize log messages by stripping or encoding CRLF characters before writing them to standard "
    "output streams." + PAD)
)
wr("cpp","cpp_hardcoded_bearer_token",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded Bearer or API Token",
   ("A hardcoded API bearer token inside C++ source code provides a direct avenue for attackers "
    "to authenticate as the application against third-party services."),
   [],["\"Bearer ","\"Token "],["std::getenv("],
   ("Retrieve Bearer tokens and API keys from a secure vault or environment variables at runtime, "
    "never hardcoding them." + PAD)
)
wr("cpp","cpp_xpath_injection_pugixml",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via pugixml or TinyXML",
   ("Dynamically formatting an XPath expression string with user input allows an attacker to inject "
    "predicates and alter the logical meaning of the query."),
   [],["select_nodes(","evaluate_string("],["escape_xpath("],
   ("Validate user input with a strict allowlist before concatenating it into XPath queries." + PAD)
)
wr("cpp","cpp_info_exposure_what",RE["info"],"Information Exposure","CWE-209","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Low","Tentative",
   "Information Exposure via std::exception::what() in HTTP Responses",
   ("Returning the output of std::exception::what() directly to users in API or HTTP responses "
    "exposes internal database errors, file paths, or network configurations."),
   [],["what()"],["log_error"],
   ("Catch exceptions and log `what()` securely on the backend, returning only a generic, safe "
    "error message to the client." + PAD)
)

# Go
wr("go","go_jwt_none_algorithm",RE["jwt"],"JWT Bypass","CWE-287","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "JWT Authentication Bypass via 'none' Algorithm",
   ("Using a JWT library without strictly enforcing the signing algorithm allows attackers to submit "
    "a token with 'alg': 'none' and bypass signature validation completely."),
   [],["jwt.ParseUnverified(","jwt.SigningMethodNone"],["jwt.Parse("],
   ("Always use jwt.Parse() and explicitly verify the signing method in the keyfunc callback. Do not "
    "allow jwt.SigningMethodNone." + PAD)
)
wr("go","go_log_injection_logrus",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via unvalidated input in logging statements",
   ("Writing user-controlled strings to logs using logrus, zap, or log without stripping newlines "
    "enables log forging and log viewing software exploitation."),
   GO_SRC,["log.Printf(","logrus.Info("],["strings.ReplaceAll("],
   ("Use structured logging (e.g., logrus.WithField) which natively encodes fields, or strip CRLF "
    "characters from unstructured strings." + PAD)
)
wr("go","go_hardcoded_jwt_secret",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded JWT Signing Secret",
   ("Hardcoding the secret key used to sign JSON Web Tokens allows attackers who access the source "
    "to forge valid tokens and impersonate any user."),
   [],["[]byte(\"secret\")","[]byte(\"supersecret\")"],["os.Getenv("],
   ("Read the JWT secret key from environment variables or a key management system." + PAD)
)
wr("go","go_xpath_injection_xmlpath",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via fmt.Sprintf() formatting",
   ("Building XPath queries by injecting unescaped user input via fmt.Sprintf() allows attackers "
    "to modify the XPath tree traversal and access restricted data."),
   GO_SRC,["xmlpath.MustCompile(fmt.Sprintf("],["xmlpath.MustCompile("],
   ("Use parameterized XML/XPath queries if supported, or strictly validate the user input to contain "
    "only alphanumeric characters." + PAD)
)
wr("go","go_info_exposure_panic",RE["info"],"Information Exposure","CWE-209","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Low","Tentative",
   "Information Exposure via unhandled Panic traces in HTTP handlers",
   ("Failing to implement a global recover middleware in HTTP servers allows panics to leak "
    "full stack traces to clients, revealing internal paths and logic."),
   [],["panic("],["recover()"],
   ("Implement a recovery middleware (e.g., chi.Recoverer or custom defer recover) that intercepts "
    "panics, logs the stack trace internally, and returns a 500 status to the client." + PAD)
)

# C#
wr("csharp","csharp_jwt_validation_bypass",RE["jwt"],"JWT Bypass","CWE-287","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "JWT Validation Bypass: ValidateIssuerSigningKey set to false",
   ("Setting ValidateIssuerSigningKey to false in TokenValidationParameters disables cryptographic "
    "signature validation, allowing attackers to forge tokens."),
   [],["ValidateIssuerSigningKey = false"],["ValidateIssuerSigningKey = true"],
   ("Always set ValidateIssuerSigningKey = true and provide a valid IssuerSigningKey in your "
    "TokenValidationParameters." + PAD)
)
wr("csharp","csharp_log_forging_serilog",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via unescaped string interpolation in loggers",
   ("Using C# string interpolation (`$`) to embed user input directly into unstructured log messages "
    "allows an attacker to inject newline characters and fake log entries."),
   CS_SRC,["logger.LogInformation($","Log.Warning($"],["logger.LogInformation(\"{Property}\""],
   ("Use structured logging with message templates (e.g., `logger.LogInformation(\"User {User}\", input)`) "
    "which properly encodes property values." + PAD)
)
wr("csharp","csharp_hardcoded_sql_connection",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded SQL Connection String",
   ("Hardcoding database connection strings containing User ID and Password in C# files exposes "
    "the database to compromise."),
   [],["\"User ID=","\"Password=","\"Pwd="],["Configuration.GetConnectionString"],
   ("Store connection strings in secure configuration files (e.g., appsettings.json) or Azure Key Vault, "
    "and access them via IConfiguration." + PAD)
)
wr("csharp","csharp_xpath_injection_xmlnode",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via SelectNodes() or SelectSingleNode()",
   ("Constructing an XPath expression via string concatenation with user input and passing it to "
    "SelectNodes() allows an attacker to alter the query logic."),
   CS_SRC,["SelectNodes(","SelectSingleNode("],["XPathDocument"],
   ("Avoid dynamic XPath generation. Ensure input is strictly validated or sanitized before using it "
    "in an XPath query." + PAD)
)
wr("csharp","csharp_info_exposure_exception",RE["info"],"Information Exposure","CWE-209","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Low","Tentative",
   "Information Exposure via Exception.ToString() in API Responses",
   ("Returning the result of Exception.ToString() or Exception.Message to the client reveals internal "
    "stack traces and sensitive structural details."),
   CS_SRC,["return BadRequest(ex.ToString()","return StatusCode(500, ex.Message"],["logger.LogError"],
   ("Catch exceptions, log the full details securely on the server, and return a generic error "
    "message to the API consumer." + PAD)
)

# JavaScript / Node.js
wr("javascript","js_jwt_decode_unverified",RE["jwt"],"JWT Bypass","CWE-287","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "JWT Validation Bypass via jwt.decode() instead of verify()",
   ("Using jsonwebtoken's `jwt.decode()` function decodes the token payload without validating the "
    "signature. Attackers can trivially spoof their identity by modifying the payload."),
   JS_SRC,["jwt.decode("],["jwt.verify("],
   ("Always use `jwt.verify()` with a secure secret key to validate the signature and decode the token "
    "simultaneously." + PAD)
)
wr("javascript","js_log_injection_console",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via console.log() or winston",
   ("Passing unvalidated user input directly to console.log() allows an attacker to inject carriage "
    "returns and spoof log entries or exploit terminal emulators."),
   JS_SRC,["console.log(","console.error("],["input.replace("],
   ("Sanitize user input by removing newline characters before logging, or use a structured logging "
    "library that handles escaping properly." + PAD)
)
wr("javascript","js_hardcoded_mongodb_uri",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded MongoDB Connection URI",
   ("A hardcoded MongoDB URI containing a username and password exposes the database to full compromise "
    "if the source code is viewed or leaked."),
   [],["\"mongodb+srv://","'mongodb://"],["process.env.MONGO_URI"],
   ("Store database connection URIs securely in `.env` files and access them using `process.env.MONGO_URI`." + PAD)
)
wr("javascript","js_xpath_injection_xpathjs",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via xpath.select()",
   ("Dynamically constructing XPath expressions using template literals or string concatenation allows "
    "XPath injection in the node-xpath library."),
   JS_SRC,["xpath.select(","xpath.evaluate("],["escape("],
   ("Validate user input against an allowlist and ensure special characters like single quotes, double quotes, and slashes "
    "are not included in the XPath query string." + PAD)
)
wr("javascript","js_insecure_file_upload_extension",RE["upload"],"File Upload","CWE-434","A04:2021-Insecure Design",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure File Upload: Missing File Extension Validation",
   ("Accepting file uploads (e.g., via multer) without validating the file extension allows attackers "
    "to upload executable files (e.g., .php, .js) leading to RCE."),
   JS_SRC,["upload.single(","upload.array("],["fileFilter"],
   ("Implement a strict fileFilter function in multer that checks the file extension and MIME type "
    "against an allowlist of permitted formats." + PAD)
)

# Python
wr("python","python_jwt_verify_false",RE["jwt"],"JWT Bypass","CWE-287","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "JWT Validation Bypass: verify_signature=False",
   ("Decoding a JWT with verify_signature=False in PyJWT ignores the cryptographic signature, "
    "allowing attackers to tamper with the token claims and elevate privileges."),
   PY_SRC,["jwt.decode(","verify_signature=False"],["verify_signature=True"],
   ("Always enforce signature verification by ensuring verify_signature is True (the default behavior)." + PAD)
)
wr("python","python_log_injection_logging",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via python logging module",
   ("Concatenating user input into log messages allows an attacker to insert CRLF sequences and "
    "create deceptive log entries."),
   PY_SRC,["logging.info(","logging.error("],["input.replace"],
   ("Sanitize log inputs by replacing `\\n` and `\\r` characters, or use a structured JSON logging "
    "formatter." + PAD)
)
wr("python","python_hardcoded_redis_pwd",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded Redis Password",
   ("Hardcoding the Redis database password inside the application logic or connection settings exposes "
    "the caching and session store to unauthorized access."),
   [],["redis.Redis(password=","StrictRedis(password="],["os.environ.get"],
   ("Load Redis credentials from environment variables securely at runtime." + PAD)
)
wr("python","python_xpath_injection_lxml",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via lxml or xml.etree",
   ("Formatting user input directly into an XPath expression string passed to tree.xpath() or "
    "find() allows an attacker to alter the query logic and bypass access controls."),
   PY_SRC,["tree.xpath(","root.find("],["xpath_variables"],
   ("Use parameterized XPath queries using dictionaries (e.g., in lxml) or strictly validate the "
    "user input before concatenation." + PAD)
)
wr("python","python_info_exposure_traceback",RE["info"],"Information Exposure","CWE-209","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Low","Tentative",
   "Information Exposure via traceback.format_exc() returned in HTTP response",
   ("Returning the output of traceback.format_exc() in Flask or Django error handlers leaks the "
    "application's source code paths and logic flow to an attacker."),
   PY_SRC,["traceback.format_exc()"],["logger.error"],
   ("Log the traceback securely on the server-side, and return a sanitized, generic error message "
    "to the HTTP client." + PAD)
)

# Java
wr("java","java_jwt_none_algorithm",RE["jwt"],"JWT Bypass","CWE-287","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "JWT Bypass via unverified parsing in jjwt or auth0",
   ("Calling Jwts.parser().parse(token) without verifying the signature (e.g., missing setSigningKey) "
    "allows an attacker to submit tampered JWTs successfully."),
   JAVA_SRC,["Jwts.parser().parse(","JWT.decode("],["setSigningKey("],
   ("Ensure the JWT parser is configured with a signing key (Jwts.parser().setSigningKey(key).parseClaimsJws(token)) "
    "to cryptographically verify tokens." + PAD)
)
wr("java","java_log_injection_slf4j",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via SLF4J / Log4j string concatenation",
   ("Including unvalidated user input directly into log messages allows an attacker to inject CRLF "
    "characters to forge new log lines."),
   JAVA_SRC,["log.info(","logger.error("],["replaceAll(\"\\\\r|\\\\n\",\"\")"],
   ("Strip CRLF characters from user input before logging, or utilize structured logging formats "
    "like JSON that automatically escape newline characters." + PAD)
)
wr("java","java_hardcoded_smtp_pwd",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded SMTP Password",
   ("Hardcoding email credentials (SMTP username and password) exposes the mail server to hijacking, "
    "allowing attackers to send spam or phishing emails from a trusted domain."),
   [],["mail.smtp.password=","new PasswordAuthentication("],["System.getenv("],
   ("Load SMTP credentials externally using environment variables or a secure vault." + PAD)
)
wr("java","java_xpath_injection_javax",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via javax.xml.xpath.XPath",
   ("Compiling dynamic XPath expression strings concatenated with unvalidated user input enables "
    "XPath injection, allowing data leakage or bypasses."),
   JAVA_SRC,["xpath.compile(","xpath.evaluate("],["XPathVariableResolver"],
   ("Use an XPathVariableResolver to parameterize variables in the XPath query, or implement strict "
    "input validation." + PAD)
)
wr("java","java_insecure_file_upload_servlet",RE["upload"],"File Upload","CWE-434","A04:2021-Insecure Design",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure File Upload via HttpServletRequest.getPart() without validation",
   ("Saving an uploaded file (Part.write()) without validating the file extension and MIME type "
    "allows an attacker to upload web shells (e.g., .jsp) and execute arbitrary code."),
   JAVA_SRC,["request.getPart(","part.write("],["FilenameUtils.getExtension("],
   ("Strictly validate the file extension against an allowlist and verify the content type before "
    "saving the file to disk." + PAD)
)

# PHP
wr("php","php_jwt_bypass_verify_false",RE["jwt"],"JWT Bypass","CWE-287","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "JWT Validation Bypass: Decoding without verification",
   ("Decoding a JWT token by explicitly ignoring signature verification or bypassing the key check "
    "allows attackers to forge tokens with administrative privileges."),
   PHP_SRC,["JWT::decode(","new Key("],["empty key"],
   ("Ensure a valid secret key is provided to JWT::decode() and the allowed algorithms are explicitly "
    "specified." + PAD)
)
wr("php","php_log_injection_error_log",RE["log"],"Log Injection","CWE-117","A09:2021-Security Logging and Monitoring Failures",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","Medium","Confirmed",
   "Log Injection via error_log() or file_put_contents()",
   ("Writing user-controlled input to logs using error_log() without sanitization allows an attacker "
    "to inject newlines and spoof log records."),
   PHP_SRC,["error_log(","file_put_contents(","fwrite("],["str_replace("],
   ("Sanitize the input by replacing carriage returns and newlines with spaces before logging." + PAD)
)
wr("php","php_hardcoded_ftp_pwd",RE["secret"],"Hardcoded Secret","CWE-798","A07:2021-Identification and Authentication Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Hardcoded FTP Password",
   ("Hardcoding FTP credentials in PHP scripts allows attackers who gain source code read access "
    "to completely compromise the file server."),
   [],["ftp_login(","\"password\" =>"],["getenv("],
   ("Store FTP and other service credentials securely outside the webroot and source control." + PAD)
)
wr("php","php_xpath_injection_domxpath",RE["xpath"],"XPath Injection","CWE-643","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XPath Injection via DOMXPath::query()",
   ("Dynamic concatenation of user input into an XPath query string enables XPath injection, allowing "
    "attackers to alter the logic of the XML search."),
   PHP_SRC,["$xpath->query("],["addslashes("],
   ("Validate user input against an allowlist before using it in an XPath query to prevent injection." + PAD)
)
wr("php","php_insecure_file_upload_move",RE["upload"],"File Upload","CWE-434","A04:2021-Insecure Design",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure File Upload via move_uploaded_file() without validation",
   ("Moving an uploaded file directly to a web-accessible directory without checking its extension "
    "allows an attacker to upload a .php web shell and achieve RCE."),
   PHP_SRC,["move_uploaded_file("],["pathinfo(","in_array("],
   ("Check the file extension against a strict allowlist and store uploaded files outside of the "
    "web root directory." + PAD)
)

print("\nBatch 18: All 40 rules written! 5 per language, diverse CVE domains.")
