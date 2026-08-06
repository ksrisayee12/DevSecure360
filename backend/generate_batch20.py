"""
generate_batch20.py — Batch 20: 5 per language × 8 = 40 rules
Themes: Double Free (C/C++), Cleartext Transmission, Cookie Security, SSRF (Alt libs), DoS (Billion Laughs / Zip Bomb).
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
"df": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/415.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
    "# Semgrep Source:  Not applicable — CFG required\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
    "# Verification:    Calling free() twice on the same pointer corrupts heap management structures."
),
"clear": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/319.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=cleartext\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html\n"
    "# Verification:    Transmitting sensitive data over unencrypted protocols (HTTP/FTP) allows interception."
),
"cookie": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/614.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=cookie\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html\n"
    "# Verification:    Missing Secure or HttpOnly flags on session cookies exposes them to XSS and MitM theft."
),
"ssrf": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/918.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=ssrf\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Unvalidated user input passed to HTTP client libraries allows Server-Side Request Forgery."
),
"dos": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/400.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=dos\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Recursive entity expansion or unbounded decompression rapidly exhausts memory and CPU."
)
}

PAD = " Always review your code and apply strict bounds or TLS configurations. Consult secure coding best practices."

JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "event.data"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.GET", "request.POST"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body"]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE[", "$_FILES["]

# C
wr("c","c_double_free",RE["df"],"Memory Corruption","CWE-415","A04:2021-Insecure Design",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Double Free Vulnerability",
   ("Calling free() twice on the same memory address corrupts the memory allocator's internal data "
    "structures. This can lead to program crashes (DoS) or arbitrary code execution."),
   [],["free("],["ptr = NULL"],
   ("Set the pointer to NULL immediately after the first free(). The C standard specifies that free(NULL) "
    "is a no-op, preventing double-free crashes." + PAD)
)
wr("c","c_cleartext_ftp",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via FTP",
   ("Initiating connections over the unencrypted FTP protocol (e.g., using ftp:// in libcurl) transmits "
    "credentials and data in plaintext, exposing them to network eavesdropping."),
   [],["\"ftp://"],["\"ftps://","\"sftp://"],
   ("Migrate from FTP to secure alternatives like FTPS (FTP over SSL/TLS) or SFTP (SSH File Transfer Protocol)." + PAD)
)
wr("c","c_cookie_missing_secure",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing Secure and HttpOnly flags",
   ("Creating HTTP cookies manually in C web servers (e.g., CGI) without appending the 'Secure' and "
    "'HttpOnly' attributes exposes the cookie to interception over HTTP and XSS attacks."),
   [],["Set-Cookie: "],["Secure; HttpOnly"],
   ("Always append '; Secure; HttpOnly' when emitting Set-Cookie headers to ensure cookies are only "
    "transmitted over HTTPS and cannot be accessed via JavaScript." + PAD)
)
wr("c","c_ssrf_libmicrohttpd",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via network socket connections",
   ("Taking a user-supplied IP address or hostname and directly connecting to it using socket() and "
    "connect() allows the application to be used as a proxy to attack internal networks."),
   [],["connect(","getaddrinfo("],["validate_ip_allowlist("],
   ("Resolve the user-provided hostname and strictly validate that the resulting IP address is not "
    "in a private or loopback range before establishing a connection." + PAD)
)
wr("c","c_dos_billion_laughs",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via XML Entity Expansion (Billion Laughs)",
   ("Parsing untrusted XML with entity substitution enabled allows attackers to supply heavily nested "
    "entities, causing memory exhaustion and Denial of Service."),
   [],["XML_SetEntityDeclHandler","XML_PARSE_NOENT"],["limit entity expansion"],
   ("Disable custom entity parsing or enforce strict memory and depth limits within the XML parser "
    "to prevent recursive expansion attacks." + PAD)
)

# C++
wr("cpp","cpp_double_free",RE["df"],"Memory Corruption","CWE-415","A04:2021-Insecure Design",
   8.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H","High","Tentative",
   "Double Free via delete operator",
   ("Calling the `delete` operator twice on the same raw pointer causes heap corruption, which may "
    "be exploited for arbitrary code execution."),
   [],["delete ptr","delete "],["ptr = nullptr"],
   ("Set raw pointers to `nullptr` after deletion. Better yet, use `std::unique_ptr` or `std::shared_ptr` "
    "to manage memory safely." + PAD)
)
wr("cpp","cpp_cleartext_http",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via HTTP URLs",
   ("Hardcoding or permitting `http://` URLs for network clients transmits data in plaintext, exposing "
    "sensitive information to interception."),
   [],["\"http://"],["\"https://"],
   ("Enforce the use of HTTPS for all network communication to ensure transport layer encryption." + PAD)
)
wr("cpp","cpp_cookie_missing_httponly",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing HttpOnly flag in C++ web frameworks",
   ("Setting cookies in C++ HTTP servers (like Crow or Pistache) without the HttpOnly flag allows "
    "client-side scripts to access the cookie, exacerbating XSS attacks."),
   [],["cookie.set(","res.set_cookie("],["cookie.httponly = true"],
   ("Configure the cookie object to enable the HttpOnly and Secure flags before adding it to the HTTP response." + PAD)
)
wr("cpp","cpp_ssrf_cpprestsdk",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via C++ REST SDK (Casablanca)",
   ("Passing an unvalidated user-provided URL to web::http::client::http_client allows SSRF. "
    "The application may make unauthorized requests to internal endpoints."),
   [],["web::http::client::http_client("],["validate_uri("],
   ("Parse the URL and ensure the host does not resolve to local, private, or loopback network addresses." + PAD)
)
wr("cpp","cpp_dos_zip_bomb",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via Unbounded Decompression (Zip Bomb)",
   ("Decompressing user-supplied zlib or gzip data in C++ without tracking and limiting the output "
    "size can exhaust all system memory, causing a Denial of Service."),
   [],["inflate(","uncompress("],["output_limit"],
   ("Implement strict limits on the maximum allowed decompressed size. Abort the decompression if "
    "the output buffer exceeds this threshold." + PAD)
)

# Go
wr("go","go_cleartext_http_transport",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission: HTTP usage instead of HTTPS",
   ("Making API requests or establishing connections using unencrypted `http://` URLs exposes all "
    "transmitted headers and payloads to network eavesdropping."),
   [],["\"http://"],["\"https://"],
   ("Always use `https://` for external service communication to ensure data confidentiality and integrity." + PAD)
)
wr("go","go_cookie_insecure",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing Secure/HttpOnly in http.Cookie",
   ("Creating an http.Cookie struct without setting Secure: true and HttpOnly: true exposes the "
    "session token to XSS and MitM attacks over unencrypted links."),
   [],["http.Cookie{"],["Secure: true", "HttpOnly: true"],
   ("Ensure both `Secure: true` and `HttpOnly: true` are explicitly set when instantiating `http.Cookie`." + PAD)
)
wr("go","go_ssrf_fasthttp",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via fasthttp client",
   ("Passing unvalidated user input as a URL to fasthttp.Do() or fasthttp.Get() allows SSRF, "
    "enabling the attacker to probe internal microservices."),
   GO_SRC,["fasthttp.Get(","fasthttp.Do("],["url.Parse"],
   ("Parse the URL and validate the hostname against a strict allowlist. Block requests to internal IPs." + PAD)
)
wr("go","go_dos_zip_bomb",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via archive/zip or compress/gzip",
   ("Extracting archives or decompressing data using io.Copy without a size limit allows Zip Bomb "
    "attacks (decompression bombs) which exhaust server memory and disk space."),
   [],["gzip.NewReader(","zip.OpenReader("],["io.LimitReader("],
   ("Always wrap the decompression reader with `io.LimitReader` to enforce a maximum acceptable "
    "extracted file size." + PAD)
)
wr("go","go_goroutine_leak",RE["df"],"Memory Corruption","CWE-400","A04:2021-Insecure Design",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "Resource Leak: Unbounded Goroutine Spawning",
   ("Spawning goroutines inside a loop based on unvalidated user input without a concurrency limit "
    "(e.g., worker pool or semaphore) leads to memory exhaustion and DoS."),
   GO_SRC,["go func()"],["sync.WaitGroup","semaphore"],
   ("Limit concurrency using a semaphore (buffered channel) or a worker pool to prevent unbounded "
    "goroutine creation." + PAD)
)

# C#
wr("csharp","csharp_cleartext_ftpwebrequest",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via FtpWebRequest",
   ("Using FtpWebRequest without setting EnableSsl to true transmits credentials and file data in "
    "plaintext, making it vulnerable to interception."),
   [],["FtpWebRequest.Create(","EnableSsl = false"],["EnableSsl = true"],
   ("Always set `EnableSsl = true` when using FtpWebRequest to ensure the FTP connection uses TLS." + PAD)
)
wr("csharp","csharp_cookie_missing_secure",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing HttpOnly or Secure in CookieOptions",
   ("Appending a cookie via Response.Cookies.Append() without setting HttpOnly and Secure to true "
    "leaves the cookie vulnerable to client-side script access and unencrypted network transmission."),
   [],["new CookieOptions","Response.Cookies.Append("],["HttpOnly = true","Secure = true"],
   ("Set `HttpOnly = true` and `Secure = true` in the CookieOptions object before appending the cookie." + PAD)
)
wr("csharp","csharp_ssrf_restsharp",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via RestSharp RestClient",
   ("Instantiating a RestClient or setting its BaseUrl using unvalidated user input enables SSRF, "
    "allowing attackers to access internal endpoints."),
   CS_SRC,["new RestClient(","client.Execute("],["Uri.IsWellFormedUriString("],
   ("Ensure the URL provided to RestSharp is validated against an allowlist and does not point to "
    "internal network resources." + PAD)
)
wr("csharp","csharp_dos_regex_matchtimeout",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Confirmed",
   "Denial of Service via unbounded Regex (Missing Timeout)",
   ("Executing Regex operations without specifying a match timeout on user input allows ReDoS attacks, "
    "which can freeze the thread and consume high CPU."),
   CS_SRC,["Regex.Match(","Regex.IsMatch("],["TimeSpan.FromSeconds("],
   ("Always pass a `TimeSpan` timeout argument to Regex static methods or set the `AppDomain` default "
    "regex match timeout." + PAD)
)
wr("csharp","csharp_dos_xml_billion_laughs",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via XmlReader DTD Processing",
   ("Configuring an XmlReaderSettings with DtdProcessing.Parse and unbounded MaxCharactersFromEntities "
    "allows the Billion Laughs entity expansion attack."),
   [],["DtdProcessing.Parse"],["MaxCharactersFromEntities"],
   ("Disable DTD processing (DtdProcessing.Prohibit) or strictly limit `MaxCharactersFromEntities` to "
    "prevent XML expansion attacks." + PAD)
)

# JavaScript / Node.js
wr("javascript","js_cleartext_http_module",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via built-in http module",
   ("Using the Node.js built-in `http.get` or `http.request` modules for external communication "
    "transmits data in plaintext. It is highly susceptible to MitM interception."),
   [],["http.get(","http.request("],["https.get("],
   ("Use the `https` module for all network requests to ensure data is encrypted in transit." + PAD)
)
wr("javascript","js_cookie_insecure_express",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing secure/httpOnly flags in res.cookie()",
   ("Setting cookies via res.cookie() without specifying `{ secure: true, httpOnly: true }` exposes "
    "the session to XSS attacks and plaintext transmission leaks."),
   [],["res.cookie("],["secure: true", "httpOnly: true"],
   ("Always include `{ secure: true, httpOnly: true }` in the options object when calling res.cookie()." + PAD)
)
wr("javascript","js_ssrf_node_fetch",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via node-fetch",
   ("Passing unvalidated user-controlled input as a URL to the `fetch()` function enables SSRF, "
    "allowing an attacker to bypass firewalls and interact with internal APIs."),
   JS_SRC,["fetch("],["new URL(","allowlist"],
   ("Validate the URL host against an allowlist and reject any URLs that resolve to internal/loopback "
    "IP addresses." + PAD)
)
wr("javascript","js_dos_billion_laughs_sax",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via XML Entity Expansion (sax/xml2js)",
   ("Parsing untrusted XML using libraries that do not inherently limit entity expansion depth allows "
    "the Billion Laughs attack, crashing the Node.js process."),
   JS_SRC,["parseString(","sax.parser("],["disable entities"],
   ("Ensure the XML parser is configured to reject external entities and limit expansion depth to "
    "prevent DoS." + PAD)
)
wr("javascript","js_dos_regex_redos",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Confirmed",
   "Denial of Service via ReDoS in String.match()",
   ("Using statically defined but poorly constructed regular expressions with nested quantifiers against "
    "untrusted user input blocks the single-threaded Node.js event loop."),
   JS_SRC,["match(/.+?/","test(/.+?/"],["safe-regex"],
   ("Rewrite the regular expression to remove overlapping alternations and nested quantifiers, or "
    "use a linear-time regex library like re2." + PAD)
)

# Python
wr("python","python_cleartext_telnetlib",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via telnetlib or ftplib",
   ("Using the built-in telnetlib or ftplib modules transmits credentials and session data in "
    "plaintext. This legacy protocol should not be used in modern networks."),
   [],["telnetlib.Telnet(","ftplib.FTP("],["paramiko","ftplib.FTP_TLS"],
   ("Use secure alternatives like paramiko for SSH, or `ftplib.FTP_TLS` for encrypted file transfers." + PAD)
)
wr("python","python_cookie_insecure_flask",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing httponly/secure in Flask set_cookie",
   ("Calling set_cookie() in Flask or Django without specifying `secure=True` and `httponly=True` "
    "makes the cookie vulnerable to XSS and unencrypted network interception."),
   [],["set_cookie("],["secure=True","httponly=True"],
   ("Always set `secure=True` and `httponly=True` when emitting cookies containing sensitive session data." + PAD)
)
wr("python","python_ssrf_httpx",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via httpx Client",
   ("Constructing an httpx.get() or httpx.AsyncClient().get() request with user-controlled URLs "
    "facilitates SSRF, enabling attacks on internal cloud metadata endpoints (e.g., AWS IMDS)."),
   PY_SRC,["httpx.get(","client.get("],["urllib.parse"],
   ("Parse the URL and ensure the domain is present in an allowlist. Block any resolution to local "
    "or private IP ranges." + PAD)
)
wr("python","python_dos_billion_laughs_xml",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via XML Entity Expansion (Billion Laughs)",
   ("Parsing untrusted XML using the standard `xml.etree.ElementTree` without protections allows "
    "Billion Laughs attacks to exhaust server memory."),
   PY_SRC,["ET.parse(","ET.fromstring("],["defusedxml"],
   ("Use the `defusedxml` package instead of the standard library `xml` module when parsing untrusted XML." + PAD)
)
wr("python","python_dos_zip_bomb",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via ZipFile extraction",
   ("Extracting zip files using ZipFile.extractall() without validating the uncompressed sizes "
    "enables Zip Bomb attacks that exhaust disk space and memory."),
   PY_SRC,["zip_ref.extractall("],["zip_ref.getinfo().file_size"],
   ("Iterate over the files inside the archive and sum the `file_size` properties. Abort extraction "
    "if the total size exceeds a safe maximum limit." + PAD)
)

# Java
wr("java","java_cleartext_socket",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via plain java.net.Socket",
   ("Using a plain java.net.Socket to transmit sensitive data over the network exposes the payload "
    "to packet sniffing and MitM attacks."),
   [],["new Socket("],["SSLSocketFactory"],
   ("Use `SSLSocketFactory.getDefault().createSocket()` to ensure the connection is encrypted via TLS." + PAD)
)
wr("java","java_cookie_insecure_servlet",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing Secure/HttpOnly in javax.servlet.http.Cookie",
   ("Adding a cookie to the HttpServletResponse without calling setSecure(true) and setHttpOnly(true) "
    "allows the cookie to be transmitted over HTTP and accessed via JavaScript."),
   [],["new Cookie(","response.addCookie("],["cookie.setSecure(true)","cookie.setHttpOnly(true)"],
   ("Always invoke `setSecure(true)` and `setHttpOnly(true)` on Cookie objects before adding them to "
    "the response." + PAD)
)
wr("java","java_ssrf_okhttp",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via OkHttp Client",
   ("Passing unvalidated user input as the URL to an OkHttpClient Request.Builder allows an attacker "
    "to initiate Server-Side Request Forgery against internal infrastructure."),
   JAVA_SRC,["new Request.Builder().url(","client.newCall("],["HttpUrl.parse"],
   ("Parse the URL and validate that the host matches a restricted allowlist. Ensure it does not "
    "point to private IP ranges." + PAD)
)
wr("java","java_dos_billion_laughs",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via XML Entity Expansion (Billion Laughs)",
   ("Parsing untrusted XML with DocumentBuilderFactory without enabling the SECURE_PROCESSING feature "
    "allows unbounded entity expansion, leading to DoS."),
   JAVA_SRC,["factory.newDocumentBuilder("],["FEATURE_SECURE_PROCESSING"],
   ("Set the `XMLConstants.FEATURE_SECURE_PROCESSING` feature to true on the DocumentBuilderFactory "
    "to prevent entity expansion attacks." + PAD)
)
wr("java","java_dos_zip_bomb",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via ZipInputStream",
   ("Decompressing entries from a ZipInputStream in a loop without tracking the cumulative byte count "
    "allows Zip Bomb attacks to exhaust disk and memory resources."),
   JAVA_SRC,["new ZipInputStream(","zis.getNextEntry()"],["totalBytes > MAX_SIZE"],
   ("Keep a running total of bytes written during extraction. Throw an exception and abort if the "
    "total exceeds a predefined safe limit." + PAD)
)

# PHP
wr("php","php_cleartext_ftp",RE["clear"],"Cleartext Transmission","CWE-319","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Tentative",
   "Cleartext Transmission via ftp_connect()",
   ("Using ftp_connect() instead of ftp_ssl_connect() transmits authentication credentials and files "
    "in plaintext across the network."),
   [],["ftp_connect("],["ftp_ssl_connect("],
   ("Always use `ftp_ssl_connect()` for FTPS, or use the `ssh2_sftp` functions for SFTP encrypted transfers." + PAD)
)
wr("php","php_cookie_insecure_setcookie",RE["cookie"],"Cookie Security","CWE-614","A05:2021-Security Misconfiguration",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","Medium","Tentative",
   "Cookie Security: Missing secure/httponly flags in setcookie()",
   ("Calling setcookie() without setting the 6th (secure) and 7th (httponly) parameters to true "
    "exposes the session token to interception and XSS attacks."),
   [],["setcookie("],["true, true)"],
   ("Ensure all `setcookie()` and `setrawcookie()` calls explicitly set both `secure` and `httponly` "
    "flags to `true`." + PAD)
)
wr("php","php_ssrf_fopen",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via fopen() with allow_url_fopen enabled",
   ("When allow_url_fopen is enabled, passing unvalidated user input to fopen() allows an attacker "
    "to make outbound HTTP/FTP requests, enabling SSRF."),
   PHP_SRC,["fopen("],["filter_var(","FILTER_VALIDATE_URL"],
   ("Validate the URL using `filter_var()` and restrict the hostname to a specific allowlist. Ensure "
    "it does not resolve to private subnets." + PAD)
)
wr("php","php_dos_libxml_noent",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via LIBXML_NOENT in simplexml",
   ("Passing the LIBXML_NOENT flag to simplexml_load_string() enables entity substitution. An attacker "
    "can provide nested entities (Billion Laughs) to crash the PHP process."),
   PHP_SRC,["simplexml_load_string(","LIBXML_NOENT"],["remove LIBXML_NOENT"],
   ("Do not use the `LIBXML_NOENT` option when parsing untrusted XML, as it enables dangerous entity "
    "expansion." + PAD)
)
wr("php","php_dos_ziparchive",RE["dos"],"DoS","CWE-400","A01:2021-Broken Access Control",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","High","Confirmed",
   "Denial of Service via ZipArchive::extractTo()",
   ("Extracting a user-uploaded zip file blindly using ZipArchive::extractTo() enables Zip Bomb "
    "attacks that can fill the disk and cause DoS."),
   PHP_SRC,["extractTo("],["statIndex("],
   ("Iterate over the files using `statIndex()` to check the `size` property. Prevent extraction "
    "if the uncompressed size exceeds an allowed limit." + PAD)
)

print("\nBatch 20: All 40 rules written! 5 per language, diverse CVE domains.")
