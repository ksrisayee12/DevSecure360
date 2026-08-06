"""
generate_batch19.py — Batch 19: 5 per language × 8 = 40 rules
Themes: Improper Certificate Validation (TLS Bypass), CORS Misconfiguration (* wildcard), 
Unsafe Reflection/Deserialization, Use After Free (C/C++), Integer Overflow (C/C++).
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
"tls": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/295.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=certificate+validation\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html\n"
    "# Verification:    Disabling TLS certificate validation allows Man-in-the-Middle (MitM) attacks. Tentative."
),
"cors": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/942.html\n"
    "# CodeQL Source:   Not applicable — config detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=cors\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Using wildcard (*) for CORS Access-Control-Allow-Origin exposes APIs to cross-origin attacks. Tentative."
),
"reflect": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/470.html\n"
    "# CodeQL Source:   Not applicable — structural detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=reflection\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html\n"
    "# Verification:    Loading classes or modules based on unvalidated user input enables arbitrary code execution."
),
"uaf": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/416.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  Not applicable — CFG required\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    Accessing a pointer after it has been freed leads to undefined behavior and potential RCE. Rule is Tentative."
),
"int_over": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/190.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  Not applicable — type inference required\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    Integer overflow without boundary checks can lead to buffer overflows or logic bypasses. Rule is Tentative."
)
}

PAD = " Always review your code and apply strict validation. Consult secure coding best practices."

JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "event.data"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.GET", "request.POST"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body"]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE[", "$_FILES["]

# C
wr("c","c_use_after_free",RE["uaf"],"Use After Free","CWE-416","A04:2021-Insecure Design",
   8.8,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Use After Free (UAF) Vulnerability",
   ("Referencing memory after it has been freed can cause a program to crash or, more severely, "
    "allow an attacker to execute arbitrary code by controlling the reallocated memory."),
   [],["free("],["ptr = NULL"],
   ("Immediately set the pointer to NULL after freeing it (e.g., `free(ptr); ptr = NULL;`). Ensure "
    "logic flow cannot access the pointer after deallocation." + PAD)
)
wr("c","c_integer_overflow_malloc",RE["int_over"],"Integer Overflow","CWE-190","A04:2021-Insecure Design",
   7.8,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Integer Overflow leading to insufficient malloc allocation",
   ("Performing arithmetic (e.g., multiplication) directly inside a malloc() call without bounds "
    "checking can lead to integer overflow, resulting in a small allocation followed by a heap overflow."),
   [],["malloc(size *","malloc(count *"],["if (size > MAX)"],
   ("Check for integer overflows before allocating memory. Ensure that `size * count` does not "
    "exceed SIZE_MAX." + PAD)
)
wr("c","c_tls_verification_disabled",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Certificate Validation in libcurl",
   ("Setting CURLOPT_SSL_VERIFYPEER to 0 (false) disables TLS certificate validation in libcurl, "
    "allowing attackers to intercept and modify traffic via Man-in-the-Middle (MitM) attacks."),
   [],["CURLOPT_SSL_VERIFYPEER, 0L","CURLOPT_SSL_VERIFYPEER, 0"],["CURLOPT_SSL_VERIFYPEER, 1L"],
   ("Do not disable SSL verification in production environments. Ensure CURLOPT_SSL_VERIFYPEER is "
    "set to 1L (the default)." + PAD)
)
wr("c","c_cors_misconfig_header",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: Access-Control-Allow-Origin: *",
   ("Hardcoding the Access-Control-Allow-Origin header to '*' allows any website to make cross-origin "
    "requests to the server and read its responses, bypassing the Same-Origin Policy."),
   [],["\"Access-Control-Allow-Origin: *\""],["allowed_origins"],
   ("Instead of a wildcard, dynamically echo the Origin header if it matches a strict server-side "
    "allowlist of permitted domains." + PAD)
)
wr("c","c_unsafe_dynamic_library_load",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Dynamic Library Loading via dlopen()",
   ("Passing unvalidated user input directly to dlopen() allows an attacker to load malicious shared "
    "objects (.so files) and execute arbitrary code in the context of the application."),
   [],["dlopen("],["realpath("],
   ("Validate the requested module name against a hardcoded list of allowed libraries. Ensure the "
    "path is absolute and restricted to a secure system directory." + PAD)
)

# C++
wr("cpp","cpp_use_after_free",RE["uaf"],"Use After Free","CWE-416","A04:2021-Insecure Design",
   8.8,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Use After Free (UAF) via delete operator",
   ("Continuing to use a raw pointer after calling `delete` on it leads to Use After Free (UAF) "
    "vulnerabilities, which can result in code execution."),
   [],["delete ptr","delete[]"],["ptr = nullptr"],
   ("Set the pointer to `nullptr` immediately after `delete`. Prefer using C++ smart pointers "
    "(std::unique_ptr, std::shared_ptr) which automatically manage memory lifecycles." + PAD)
)
wr("cpp","cpp_integer_overflow_new",RE["int_over"],"Integer Overflow","CWE-190","A04:2021-Insecure Design",
   7.8,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Integer Overflow leading to insufficient std::new allocation",
   ("Performing unchecked arithmetic inside a `new[]` array allocation can cause an integer overflow, "
    "resulting in a much smaller buffer than expected, leading to heap corruption."),
   [],["new char[size *","new int["],["std::numeric_limits"],
   ("Validate arithmetic operations using std::numeric_limits to ensure they do not wrap around "
    "before allocating memory arrays." + PAD)
)
wr("cpp","cpp_tls_verification_disabled_poco",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Certificate Validation in POCO C++",
   ("Initializing a POCO Context with Context::VERIFY_NONE disables TLS certificate validation, "
    "making connections vulnerable to interception (MitM)."),
   [],["Context::VERIFY_NONE"],["Context::VERIFY_RELAXED","Context::VERIFY_STRICT"],
   ("Use Context::VERIFY_STRICT or VERIFY_RELAXED to ensure the server's certificate is properly "
    "validated against trusted root CAs." + PAD)
)
wr("cpp","cpp_cors_misconfig_crow",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration in Crow / C++ Web Framework",
   ("Adding a global HTTP header `Access-Control-Allow-Origin: *` permits arbitrary websites to "
    "make authenticated requests and read sensitive data."),
   [],["add_header(\"Access-Control-Allow-Origin\", \"*\")"],["Origin allowlist"],
   ("Configure CORS dynamically by checking the Origin header of the request against an allowlist "
    "before echoing it back." + PAD)
)
wr("cpp","cpp_unsafe_reflection_plugin",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Plugin Loading via LoadLibrary() / dlopen()",
   ("Loading DLLs or SOs dynamically based on user-supplied strings without validation allows "
    "attackers to execute arbitrary code (DLL Hijacking / Plugin Injection)."),
   [],["LoadLibrary(","dlopen("],["whitelist check"],
   ("Use a strict allowlist of permitted plugin names. Never load libraries from paths directly "
    "provided by untrusted users." + PAD)
)

# Go
wr("go","go_tls_insecure_skip_verify",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Certificate Validation: InsecureSkipVerify: true",
   ("Setting InsecureSkipVerify to true in Go's crypto/tls Config disables TLS certificate checking, "
    "allowing attackers to perform Man-in-the-Middle (MitM) attacks."),
   [],["InsecureSkipVerify: true","InsecureSkipVerify:true"],["InsecureSkipVerify: false"],
   ("Remove InsecureSkipVerify: true from production code. Let the default Go behavior validate "
    "TLS certificates securely." + PAD)
)
wr("go","go_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: Access-Control-Allow-Origin wildcard",
   ("Writing a hardcoded '*' to the Access-Control-Allow-Origin HTTP header in Go disables Same-Origin "
    "protections for the endpoint."),
   [],["w.Header().Set(\"Access-Control-Allow-Origin\", \"*\")"],["allowed_origins slice"],
   ("Check the request's Origin header against a slice of allowed domains and set the response header "
    "dynamically to match the valid Origin." + PAD)
)
wr("go","go_unsafe_reflection_plugin",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Plugin Loading via plugin.Open()",
   ("Opening a Go plugin dynamically based on user-supplied file paths allows an attacker to load "
    "a malicious plugin and execute arbitrary init() functions."),
   GO_SRC,["plugin.Open("],["filepath.Base"],
   ("Restrict plugin loading to a secure, hardcoded directory, and validate the requested plugin "
    "name against a strict allowlist." + PAD)
)
wr("go","go_integer_overflow_make",RE["int_over"],"Integer Overflow","CWE-190","A04:2021-Insecure Design",
   7.8,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Integer Overflow in slice make() capacity",
   ("Using unvalidated arithmetic operations (e.g., multiplication) to determine the size/capacity "
    "of a slice in make() can wrap around on 32-bit systems, causing panics or memory corruption."),
   GO_SRC,["make([]byte, size*","make([]int, size*"],["math.MaxInt32"],
   ("Perform bounds checking on integers before using them in arithmetic operations for memory "
    "allocations." + PAD)
)
wr("go","go_use_after_free_cgo",RE["uaf"],"Use After Free","CWE-416","A04:2021-Insecure Design",
   8.8,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Use After Free in CGO C.free()",
   ("Freeing a C pointer via C.free() in Go, but continuing to use the Go slice that aliases that "
    "memory, results in a Use After Free vulnerability."),
   [],["C.free("],["nil"],
   ("Ensure that any Go slices or variables aliasing C memory are not accessed after C.free() is called." + PAD)
)

# C#
wr("csharp","csharp_tls_validation_bypass",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: ServerCertificateCustomValidationCallback returns true",
   ("Configuring HttpClientHandler's ServerCertificateCustomValidationCallback to always return true "
    "ignores certificate errors and enables MitM attacks."),
   [],["ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true",
       "ServerCertificateValidationCallback = delegate { return true; }"],["return sslPolicyErrors == SslPolicyErrors.None;"],
   ("Remove custom validation callbacks that bypass security. Allow the framework to natively "
    "validate the certificate trust chain." + PAD)
)
wr("csharp","csharp_cors_wildcard",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: AllowAnyOrigin()",
   ("Configuring the ASP.NET Core CORS policy with AllowAnyOrigin() alongside credentials or "
    "sensitive endpoints exposes the application to cross-origin data theft."),
   [],["builder.AllowAnyOrigin()",".AllowAnyOrigin()"],["WithOrigins("],
   ("Specify allowed origins explicitly using `.WithOrigins(\"https://trusted.com\")` instead of "
    "permitting any origin." + PAD)
)
wr("csharp","csharp_unsafe_reflection_activator",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Reflection via Activator.CreateInstance()",
   ("Instantiating types dynamically using Activator.CreateInstance() with user-controlled type "
    "names allows an attacker to instantiate dangerous classes (e.g., Process)."),
   CS_SRC,["Activator.CreateInstance(Type.GetType("],["whitelist.Contains"],
   ("Do not instantiate classes directly from user input. Map user inputs to safe, predefined types "
    "using a dictionary or switch statement." + PAD)
)
wr("csharp","csharp_unsafe_reflection_assembly_load",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Assembly Loading via Assembly.Load()",
   ("Loading assemblies dynamically based on user input allows an attacker to load malicious code "
    "into the application domain, leading to RCE."),
   CS_SRC,["Assembly.Load(","Assembly.LoadFile("],["allowlist"],
   ("Restrict assembly loading to a fixed list of known, signed assemblies." + PAD)
)
wr("csharp","csharp_integer_overflow_unchecked",RE["int_over"],"Integer Overflow","CWE-190","A04:2021-Insecure Design",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L","Medium","Tentative",
   "Integer Overflow in unchecked context",
   ("Performing mathematical operations in an `unchecked` block (or by default in C#) can lead to "
    "silent integer overflows, breaking application logic."),
   [],["unchecked {"],["checked {"],
   ("Wrap sensitive mathematical calculations in a `checked { }` block so that overflows throw an "
    "OverflowException instead of failing silently." + PAD)
)

# JavaScript / Node.js
wr("javascript","js_tls_reject_unauthorized",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: rejectUnauthorized: false",
   ("Setting rejectUnauthorized: false in Node.js HTTPS requests or Axios configurations disables "
    "TLS certificate verification, exposing the request to MitM attacks."),
   [],["rejectUnauthorized: false","rejectUnauthorized:false"],["rejectUnauthorized: true"],
   ("Ensure rejectUnauthorized is set to true (or omitted, as true is the default) in production "
    "environments to validate server certificates." + PAD)
)
wr("javascript","js_cors_wildcard_express",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: wildcard origin in Express",
   ("Configuring the cors() middleware or setting Access-Control-Allow-Origin to '*' allows any "
    "site to read responses from the API."),
   [],["cors({ origin: '*' })","res.setHeader('Access-Control-Allow-Origin', '*')"],["cors({ origin: 'https://trusted.com' })"],
   ("Configure the CORS origin property to explicitly match trusted frontend domains rather than "
    "allowing all origins." + PAD)
)
wr("javascript","js_unsafe_dynamic_import",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Dynamic Import / Require",
   ("Passing user-controlled input directly to require() or import() allows attackers to load "
    "arbitrary local files or malicious modules, leading to RCE (Local File Inclusion / Module Hijacking)."),
   JS_SRC,["require(","import("],["allowlist_check"],
   ("Do not load modules dynamically based on user input. If necessary, use a switch statement or "
    "strict allowlist mapping." + PAD)
)
wr("javascript","js_integer_overflow_bitwise",RE["int_over"],"Integer Overflow","CWE-190","A04:2021-Insecure Design",
   5.5,"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L","Medium","Tentative",
   "Integer Overflow / Truncation via Bitwise Operators",
   ("Using bitwise operators (e.g., `| 0` or `<<`) in JavaScript truncates the Number to a 32-bit "
    "signed integer. If the original number is large, this silently overflows and alters logic."),
   [],["| 0","<< 0"],["Math.floor("],
   ("Avoid bitwise operators for rounding or type coercion of large numbers. Use Math.floor() or "
    "BigInt for safe arithmetic." + PAD)
)
wr("javascript","js_tls_env_node_tls_reject_unauthorized",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: NODE_TLS_REJECT_UNAUTHORIZED = '0'",
   ("Setting the environment variable NODE_TLS_REJECT_UNAUTHORIZED to '0' globally disables TLS "
    "certificate verification for the entire Node.js process."),
   [],["process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'","process.env.NODE_TLS_REJECT_UNAUTHORIZED = \"0\""],["delete process.env"],
   ("Never disable TLS validation globally. Handle self-signed certificates properly by providing "
    "a custom CA bundle in the request agent." + PAD)
)

# Python
wr("python","python_tls_verify_false",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: requests verify=False",
   ("Passing verify=False to requests.get() or requests.post() disables SSL/TLS certificate verification, "
    "permitting MitM attacks on the connection."),
   [],["verify=False","verify=0"],["verify=True"],
   ("Ensure verify=True is used (or omitted, as it is the default). If using custom certificates, "
    "pass the path to the CA bundle instead of disabling verification." + PAD)
)
wr("python","python_cors_wildcard_flask",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: Flask-CORS wildcard",
   ("Configuring CORS(app, resources={r\"/*\": {\"origins\": \"*\"}}) allows any origin to interact "
    "with the API, which can leak sensitive data to malicious domains."),
   [],["origins\": \"*\"","origins='*'"],["origins_list"],
   ("Specify a precise list of trusted origins for the CORS configuration." + PAD)
)
wr("python","python_unsafe_reflection_import",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Reflection via __import__ or importlib",
   ("Loading Python modules dynamically using user input (e.g., __import__(user_input)) allows "
    "attackers to execute unintended code or exploit local file inclusion."),
   PY_SRC,["__import__(","importlib.import_module("],["allowed_modules"],
   ("Avoid dynamic imports based on user input. Restrict imports to an explicit allowlist." + PAD)
)
wr("python","python_unsafe_reflection_eval",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Code Execution via eval()",
   ("Passing user input into the built-in eval() function executes it as Python code, resulting in "
    "immediate Remote Code Execution."),
   PY_SRC,["eval("],["ast.literal_eval("],
   ("Never use eval() on untrusted data. Use ast.literal_eval() to safely parse strings into Python "
    "literals (dictionaries, lists, etc.)." + PAD)
)
wr("python","python_tls_ssl_unverified_context",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: ssl._create_unverified_context",
   ("Using ssl._create_unverified_context() globally disables certificate verification for urllib, "
    "undermining the security of all HTTPS requests in the application."),
   [],["ssl._create_unverified_context("],["ssl.create_default_context("],
   ("Use ssl.create_default_context() which validates certificates against the system's trusted CAs." + PAD)
)

# Java
wr("java","java_tls_trust_all_manager",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: Trusting all certificates",
   ("Implementing an X509TrustManager that has empty checkClientTrusted and checkServerTrusted "
    "methods accepts all SSL certificates, completely breaking TLS security."),
   [],["implements X509TrustManager","checkClientTrusted","checkServerTrusted"],["return false"],
   ("Do not use TrustAll managers. Ensure the TrustManager performs strict cryptographic verification "
    "of the certificate chain." + PAD)
)
wr("java","java_cors_wildcard_spring",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: Spring @CrossOrigin(\"*\")",
   ("Applying the @CrossOrigin(\"*\") annotation to Spring Controllers exposes the endpoints to "
    "requests from any origin, violating the principle of least privilege."),
   [],["@CrossOrigin(\"*\")","registry.addMapping(\"/**\").allowedOrigins(\"*\")"],["allowedOrigins(\"https://trust.com\")"],
   ("Specify allowed origins explicitly using the allowedOrigins attribute, avoiding the wildcard '*'." + PAD)
)
wr("java","java_unsafe_reflection_class_forname",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Reflection via Class.forName()",
   ("Using unvalidated user input as the class name for Class.forName() allows attackers to instantiate "
    "arbitrary classes, bypassing application logic and potentially achieving RCE."),
   JAVA_SRC,["Class.forName("],["allowlist.contains("],
   ("Avoid reflective instantiation from user input. Map user inputs to safe classes using a strict "
    "allowlist." + PAD)
)
wr("java","java_unsafe_reflection_method_invoke",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Reflection via Method.invoke()",
   ("Allowing an attacker to control the method name and parameters invoked reflectively via "
    "Method.invoke() can lead to unauthorized function execution and RCE."),
   JAVA_SRC,["Method.invoke("],["allowedMethods.contains("],
   ("Restrict reflective method invocation to a hardcoded list of safe, intended methods." + PAD)
)
wr("java","java_tls_hostname_verifier",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: HostnameVerifier returning true",
   ("Implementing a custom HostnameVerifier that simply returns true ignores hostname mismatches "
    "in TLS certificates, leaving the connection vulnerable to MitM attacks."),
   [],["implements HostnameVerifier","return true;"],["SSLParameters.setEndpointIdentificationAlgorithm"],
   ("Do not bypass hostname verification. Allow the default Java hostname verifier to ensure the "
    "certificate matches the requested host." + PAD)
)

# PHP
wr("php","php_tls_curl_verifyhost",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: CURLOPT_SSL_VERIFYHOST set to 0",
   ("Setting CURLOPT_SSL_VERIFYHOST to 0 (false) in PHP cURL disables verification that the "
    "server certificate matches the requested hostname, enabling MitM attacks."),
   [],["CURLOPT_SSL_VERIFYHOST, 0","CURLOPT_SSL_VERIFYHOST, false"],["CURLOPT_SSL_VERIFYHOST, 2"],
   ("Ensure CURLOPT_SSL_VERIFYHOST is set to 2 (the secure default) to properly validate the "
    "certificate hostname." + PAD)
)
wr("php","php_tls_curl_verifypeer",RE["tls"],"Misconfiguration","CWE-295","A02:2021-Cryptographic Failures",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Tentative",
   "Improper TLS Validation: CURLOPT_SSL_VERIFYPEER set to false",
   ("Setting CURLOPT_SSL_VERIFYPEER to false disables cryptographic validation of the TLS certificate "
    "chain in PHP cURL requests, breaking transport layer security."),
   [],["CURLOPT_SSL_VERIFYPEER, 0","CURLOPT_SSL_VERIFYPEER, false"],["CURLOPT_SSL_VERIFYPEER, true"],
   ("Always set CURLOPT_SSL_VERIFYPEER to true. Configure CURLOPT_CAINFO if using custom roots." + PAD)
)
wr("php","php_unsafe_reflection_class",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Reflection via ReflectionClass",
   ("Instantiating a new ReflectionClass or calling variable classes (e.g., new $className()) using "
    "unvalidated user input allows attackers to instantiate arbitrary objects and bypass logic."),
   PHP_SRC,["new ReflectionClass(","new $class("],["in_array("],
   ("Do not instantiate classes directly from user strings. Use an array map to link user input to "
    "safe, predefined class names." + PAD)
)
wr("php","php_cors_wildcard_header",RE["cors"],"Misconfiguration","CWE-942","A05:2021-Security Misconfiguration",
   6.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","Medium","Tentative",
   "CORS Misconfiguration: Wildcard header()",
   ("Outputting `header(\"Access-Control-Allow-Origin: *\")` allows any external domain to make "
    "cross-origin requests and read sensitive PHP API responses."),
   [],["header(\"Access-Control-Allow-Origin: *\")"],["in_array($_SERVER['HTTP_ORIGIN']"],
   ("Check the $_SERVER['HTTP_ORIGIN'] against a strict array of permitted domains, and echo it "
    "back if it matches." + PAD)
)
wr("php","php_unsafe_reflection_call_user_func",RE["reflect"],"Code Injection","CWE-470","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Unsafe Code Execution via call_user_func()",
   ("Passing user input as the callback parameter to call_user_func() or call_user_func_array() "
    "allows an attacker to execute arbitrary PHP functions (e.g., system)."),
   PHP_SRC,["call_user_func(","call_user_func_array("],["in_array("],
   ("Restrict the callback function to a predefined allowlist of safe functions. Never pass raw user "
    "input as the callable." + PAD)
)

print("\nBatch 19: All 40 rules written! 5 per language, diverse CVE domains.")
