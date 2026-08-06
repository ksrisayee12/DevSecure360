"""
generate_batch17.py — Batch 17: 5 per language × 8 = 40 rules
Themes: ReDoS, XXE, SSRF variations, DES/3DES/RC4 Weak Crypto, 
Arbitrary File Delete (Path Traversal), SSTI, YAML Deserialization.
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
"redos": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/1333.html\n"
    "# CodeQL Source:   Not applicable — pattern-based regex detection\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=redos\n"
    "# OWASP Cheat:     https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS\n"
    "# Verification:    ReDoS detection is pattern-based on catastrophic backtracking regex literals. Rule is Tentative."
),
"xxe": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/611.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=xxe\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\n"
    "# Verification:    XML parsers processing untrusted data without disabling DTDs allow XXE attacks."
),
"ssrf": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/918.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=ssrf\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Unvalidated user input used as a URL to make outgoing HTTP requests enables SSRF."
),
"crypto": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/327.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=weak+crypto\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html\n"
    "# Verification:    DES, 3DES, and RC4 are cryptographically broken algorithms."
),
"pt": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/22.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=path+traversal\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html\n"
    "# Verification:    Directory traversal in file delete/upload functions allows destructive actions or RCE."
),
"ssti": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/94.html\n"
    "# CodeQL Source:   Not applicable — pattern-based\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=ssti\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html\n"
    "# Verification:    Passing user input directly as a template string leads to Template Injection (SSTI)."
),
"deser": (
    "# RESEARCH EVIDENCE\n"
    "# CWE Source:      https://cwe.mitre.org/data/definitions/502.html\n"
    "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
    "# Semgrep Source:  https://semgrep.dev/r?q=deserialization\n"
    "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html\n"
    "# Verification:    Unsafe deserialization (e.g., yaml.load without SafeLoader) allows arbitrary code execution."
)
}

PAD = " Always ensure input validation and consult language-specific security documentation."

JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "event.data"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.GET", "request.POST"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body"]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE["]

# C
wr("c","c_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of DES or 3DES",
   ("DES and 3DES (Triple DES) are cryptographically weak due to small block and key sizes, making "
    "them susceptible to brute-force and collision attacks (e.g., Sweet32)."),
   [],["DES_encrypt1(","DES_set_key(","EVP_des_"],["EVP_aes_"],
   ("Migrate from DES or 3DES to AES (Advanced Encryption Standard) with an authenticated mode like "
    "GCM (Galois/Counter Mode)." + PAD)
)
wr("c","c_path_traversal_unlink",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via unlink()",
   ("Passing unvalidated user input to unlink() or remove() allows a directory traversal attack "
    "where an attacker can delete sensitive system or application files."),
   [],["unlink(","remove("],["realpath(","basename("],
   ("Ensure the file to be deleted is restricted to a specific directory by stripping directory "
    "sequences (e.g., using basename()) before passing to unlink()." + PAD)
)
wr("c","c_redos_regex_match",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "Regular Expression Denial of Service (ReDoS)",
   ("Applying a complex regular expression with catastrophic backtracking against user-supplied "
    "input can cause extreme CPU consumption and lead to a Denial of Service."),
   [],["regexec("],["timeout("],
   ("Avoid nested quantifiers (e.g., `(a+)+`) and overlapping alternations in regular expressions. "
    "Consider using a regex engine with guaranteed linear-time matching like RE2." + PAD)
)
wr("c","c_xxe_libxml2",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XML External Entity (XXE) via libxml2 parsing",
   ("Parsing untrusted XML data with libxml2 while external entity resolution (XML_PARSE_NOENT) "
    "is enabled permits XXE attacks, resulting in file disclosure or SSRF."),
   [],["xmlReadMemory(","xmlReadFile("],["XML_PARSE_NOENT"],
   ("Explicitly disable DTD processing and external entity resolution by not passing the XML_PARSE_NOENT "
    "flag when parsing untrusted XML." + PAD)
)
wr("c","c_ssrf_curl_setopt",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via curl_easy_setopt()",
   ("Using unvalidated user input to set the CURLOPT_URL in libcurl allows an attacker to make "
    "unauthorized HTTP requests to internal IP addresses or sensitive cloud metadata endpoints."),
   [],["CURLOPT_URL"],["validate_url("],
   ("Verify the host and IP address of the user-provided URL against an allowlist, ensuring it "
    "does not resolve to localhost or private network address spaces." + PAD)
)

# C++
wr("cpp","cpp_weak_crypto_rc4",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of RC4",
   ("RC4 is a broken stream cipher with known statistical biases in its keystream. Using it for "
    "encryption compromises the confidentiality of the data."),
   [],["RC4(","RC4_set_key("],["EVP_aes_"],
   ("Replace the RC4 stream cipher with a modern algorithm like AES-GCM or ChaCha20-Poly1305." + PAD)
)
wr("cpp","cpp_path_traversal_remove",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via std::remove or std::filesystem::remove",
   ("Using unvalidated user input as the path for std::remove() allows an attacker to traverse "
    "directories and delete arbitrary files."),
   [],["std::remove(","std::filesystem::remove("],["std::filesystem::canonical(","basename("],
   ("Validate the filename using std::filesystem::path::filename() to strip directory components, "
    "ensuring deletion only occurs within a sandboxed directory." + PAD)
)
wr("cpp","cpp_redos_std_regex",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "ReDoS via std::regex_match or std::regex_search",
   ("The C++ std::regex engine uses backtracking and is susceptible to ReDoS when executing "
    "complex patterns against maliciously crafted user input."),
   [],["std::regex_match(","std::regex_search("],["RE2"],
   ("Avoid complex regular expressions with nested quantifiers. Consider using Google's RE2 library "
    "which provides linear-time guarantees and prevents ReDoS." + PAD)
)
wr("cpp","cpp_xxe_xerces",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XXE via Apache Xerces-C++",
   ("Parsing untrusted XML with Xerces-C++ without disabling DTDs or external entities allows "
    "attackers to read arbitrary files via XXE attacks."),
   [],["parser->parse("],["setDisableDefaultEntityResolution(true)"],
   ("Configure the Xerces parser to ignore external DTDs and disable entity resolution before "
    "parsing untrusted XML data." + PAD)
)
wr("cpp","cpp_ssrf_poco",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via POCO HTTPClientSession",
   ("Passing user-provided host and port directly to Poco::Net::HTTPClientSession enables SSRF, "
    "allowing attackers to access internal services and bypass network restrictions."),
   [],["new Poco::Net::HTTPClientSession("],["validate_host("],
   ("Ensure the hostname or IP address resolves to a public address space before initiating an "
    "HTTPClientSession using the POCO C++ Libraries." + PAD)
)

# Go
wr("go","go_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of crypto/des",
   ("The crypto/des package implements DES and 3DES. These algorithms are obsolete and vulnerable "
    "to brute-force and collision attacks. They must not be used for secure encryption."),
   [],["des.NewCipher(","des.NewTripleDESCipher("],["aes.NewCipher("],
   ("Replace crypto/des with crypto/aes and use an authenticated encryption mode such as AES-GCM." + PAD)
)
wr("go","go_path_traversal_os_remove",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via os.Remove()",
   ("Constructing file paths with unvalidated user input and passing them to os.Remove() enables "
    "directory traversal, allowing the deletion of arbitrary files."),
   GO_SRC,["os.Remove(","os.RemoveAll("],["filepath.Base("],
   ("Sanitize the filename with filepath.Base() and ensure the resulting path remains within the "
    "intended target directory." + PAD)
)
wr("go","go_redos_regexp",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "ReDoS (Go regexp engine is generally safe, but complex parsing can still degrade performance)",
   ("While Go's regexp package uses RE2 and guarantees linear time, very large inputs or poorly "
    "structured repetitive patterns may still consume excessive CPU resources."),
   [],["regexp.MustCompile(","regexp.MatchString("],["time.After"],
   ("Go's regexp package is natively resistant to catastrophic backtracking. However, enforce strict "
    "length limits on input strings to prevent overall resource exhaustion." + PAD)
)
wr("go","go_ssrf_http_client_do",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via http.Client.Do() or http.NewRequest()",
   ("Building an http.Request with an unvalidated user-supplied URL and executing it via "
    "http.Client.Do() allows Server-Side Request Forgery."),
   GO_SRC,["http.NewRequest(","client.Do("],["url.Parse("],
   ("Parse the URL using net/url and ensure the hostname resolves strictly to public, non-internal "
    "IP addresses before initiating the request." + PAD)
)
wr("go","go_ssti_text_template",RE["ssti"],"Code Injection","CWE-94","A03:2021-Injection",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","High","Confirmed",
   "Template Injection via text/template or html/template",
   ("Parsing user-controlled strings as template definitions (e.g., template.New().Parse(input)) "
    "allows Server-Side Template Injection, potentially leading to information disclosure or RCE."),
   GO_SRC,["template.New(",").Parse("],["template.ParseFiles("],
   ("Never parse user input directly as a template structure. Load static templates from files "
    "and pass user input strictly as template data parameters." + PAD)
)

# C#
wr("csharp","csharp_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of DESCryptoServiceProvider",
   ("System.Security.Cryptography.DESCryptoServiceProvider implements the obsolete DES algorithm, "
    "which is vulnerable to brute-force attacks and offers insufficient security."),
   [],["DESCryptoServiceProvider","TripleDESCryptoServiceProvider"],["AesCryptoServiceProvider","Aes.Create("],
   ("Use System.Security.Cryptography.Aes.Create() (AES) instead of DES or 3DES for data encryption." + PAD)
)
wr("csharp","csharp_path_traversal_file_delete",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via File.Delete()",
   ("Passing an unvalidated user string to File.Delete() permits directory traversal (../), "
    "enabling an attacker to delete sensitive configuration or application files."),
   CS_SRC,["File.Delete("],["Path.GetFileName("],
   ("Use Path.GetFileName() to sanitize the user input, ensuring only the intended file within a "
    "specific sandboxed directory is targeted." + PAD)
)
wr("csharp","csharp_redos_regex",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "ReDoS via System.Text.RegularExpressions.Regex",
   ("Evaluating untrusted input against a Regex containing complex overlapping quantifiers can "
    "result in catastrophic backtracking and a Denial of Service."),
   CS_SRC,["Regex.IsMatch(","Regex.Match("],["TimeSpan("],
   ("Specify a timeout when instantiating the Regex (e.g., using a TimeSpan) to limit evaluation "
    "time and prevent ReDoS attacks." + PAD)
)
wr("csharp","csharp_ssrf_webclient",RE["ssrf"],"SSRF","CWE-918","A01:2021-Broken Access Control",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "SSRF via WebClient.DownloadString()",
   ("Using unvalidated user input as a URL in WebClient (DownloadString, DownloadData) allows SSRF, "
    "enabling unauthorized requests to internal network services."),
   CS_SRC,["WebClient().DownloadString(","client.DownloadData("],["Uri.IsWellFormedUriString("],
   ("Validate the destination URL against an allowlist. Ensure it uses HTTP/HTTPS and does not "
    "resolve to private, local, or loopback IP ranges." + PAD)
)
wr("csharp","csharp_deserialization_yaml",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure Deserialization via YamlDotNet",
   ("Using YamlDotNet to deserialize untrusted YAML without configuring it strictly can lead to "
    "arbitrary code execution if type instantiation is permitted."),
   CS_SRC,["new DeserializerBuilder()","yaml.Deserialize("],["WithNodeTypeResolver("],
   ("Configure the DeserializerBuilder securely by restricting allowed types, or avoid deserializing "
    "untrusted YAML into complex object types." + PAD)
)

# JavaScript / Node.js
wr("javascript","js_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of DES or RC4 in crypto module",
   ("Instantiating crypto.createCipher() or createCipheriv() with 'des', 'des3', or 'rc4' utilizes "
    "broken cryptographic algorithms vulnerable to various attacks."),
   [],["crypto.createCipher('des'","crypto.createCipheriv('rc4'"],["crypto.createCipheriv('aes-256-gcm'"],
   ("Use strong algorithms like 'aes-256-gcm' with crypto.createCipheriv(). Do not use deprecated "
    "algorithms like DES or RC4." + PAD)
)
wr("javascript","js_path_traversal_fs_unlink",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via fs.unlink()",
   ("Passing unvalidated user input to fs.unlink() allows directory traversal, enabling attackers "
    "to delete critical application or system files."),
   JS_SRC,["fs.unlink(","fs.unlinkSync("],["path.basename("],
   ("Sanitize the filename by using path.basename() and validating that the resolved path points "
    "inside the permitted file storage directory." + PAD)
)
wr("javascript","js_redos_regex",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "ReDoS via RegExp constructor",
   ("Dynamically constructing regular expressions using unvalidated user input (new RegExp(input)) "
    "can introduce ReDoS vulnerabilities or alter expected parsing logic."),
   JS_SRC,["new RegExp("],["re2"],
   ("Avoid building RegExp objects directly from user input. If necessary, escape the input securely "
    "or use a robust regex library like node-re2." + PAD)
)
wr("javascript","js_ssti_ejs",RE["ssti"],"Code Injection","CWE-94","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Server-Side Template Injection (SSTI) in EJS/Pug",
   ("Rendering templates dynamically with unvalidated user input as the template string (e.g., "
    "ejs.render(input)) allows attackers to inject malicious template code, leading to RCE."),
   JS_SRC,["ejs.render(","pug.render("],["res.render("],
   ("Pass user input only as the data context/locals argument. Never use user input to construct "
    "the template string itself." + PAD)
)
wr("javascript","js_xxe_libxmljs",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XXE via libxmljs parsing with noent enabled",
   ("Parsing untrusted XML using libxmljs with the { noent: true } option enables entity expansion, "
    "leading to XML External Entity (XXE) attacks."),
   JS_SRC,["libxmljs.parseXmlString(","noent: true"],["noent: false"],
   ("Ensure external entity resolution is disabled by omitting { noent: true } when parsing XML "
    "from untrusted sources." + PAD)
)

# Python
wr("python","python_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of DES or ARC4 via pycryptodome/cryptography",
   ("The DES, 3DES, and RC4 ciphers are considered broken and provide inadequate security against "
    "modern cryptographic attacks."),
   [],["DES.new(","ARC4.new("],["AES.new("],
   ("Use AES encryption with a secure mode (like GCM) via the cryptography package or PyCryptodome." + PAD)
)
wr("python","python_path_traversal_os_remove",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via os.remove() or os.unlink()",
   ("Using unvalidated user input to specify a path for os.remove() allows a directory traversal "
    "attack that can delete sensitive files."),
   PY_SRC,["os.remove(","os.unlink("],["os.path.basename("],
   ("Strip directory segments using os.path.basename() or secure_filename() and ensure the target "
    "file resides strictly in the allowed upload/storage directory." + PAD)
)
wr("python","python_ssti_jinja2",RE["ssti"],"Code Injection","CWE-94","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Server-Side Template Injection (SSTI) in Jinja2",
   ("Passing user input directly as a template string to Jinja2's Template() constructor allows "
    "attackers to execute arbitrary Python code via SSTI payloads (e.g., {{config.__class__}})."),
   PY_SRC,["Template(","render_template_string("],["render_template("],
   ("Never build Jinja templates dynamically with user input. Use static template files and pass "
    "input securely via context variables (e.g., render_template)." + PAD)
)
wr("python","python_xxe_lxml",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XXE via lxml XMLParser with resolve_entities=True",
   ("Configuring the lxml XMLParser with resolve_entities=True allows the processing of external "
    "entities, exposing the application to XXE attacks when parsing untrusted data."),
   PY_SRC,["lxml.etree.XMLParser(","resolve_entities=True"],["resolve_entities=False"],
   ("Instantiate lxml's XMLParser with resolve_entities=False to prevent external entity processing." + PAD)
)
wr("python","python_deserialization_yaml",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure Deserialization via yaml.load()",
   ("Using yaml.load() without specifying the SafeLoader on untrusted YAML allows an attacker to "
    "instantiate arbitrary Python objects and execute code."),
   PY_SRC,["yaml.load("],["yaml.safe_load("],
   ("Always use yaml.safe_load() instead of yaml.load() when parsing untrusted YAML data." + PAD)
)

# Java
wr("java","java_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of DES or RC4",
   ("Instantiating a Cipher with 'DES', 'DESede' (3DES), or 'RC4' uses algorithms that are no longer "
    "considered secure against modern cryptanalysis."),
   [],["Cipher.getInstance(\"DES\"","Cipher.getInstance(\"RC4\""],["Cipher.getInstance(\"AES/GCM/NoPadding\")"],
   ("Replace legacy ciphers with AES/GCM/NoPadding for strong authenticated encryption." + PAD)
)
wr("java","java_path_traversal_file_delete",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via File.delete()",
   ("Using unvalidated user input to specify a path for File.delete() or Files.delete() allows "
    "directory traversal, potentially causing data loss or denial of service."),
   JAVA_SRC,["file.delete(","Files.delete("],["Paths.get("],
   ("Sanitize the filename to strip directory traversal payloads and ensure the canonical path "
    "verifies it lies within the required target directory." + PAD)
)
wr("java","java_redos_pattern",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "ReDoS via java.util.regex.Pattern",
   ("Compiling regular expressions from untrusted input or evaluating complex static regexes against "
    "long malicious strings can cause catastrophic backtracking in Java's Regex engine."),
   JAVA_SRC,["Pattern.compile(","matcher.matches("],["RE2J"],
   ("Avoid complex regex structures with nested quantifiers. Limit the input length strictly, or use "
    "the RE2J library which guarantees linear-time execution." + PAD)
)
wr("java","java_xxe_documentbuilder",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XXE via DocumentBuilderFactory",
   ("Parsing XML with DocumentBuilderFactory without actively disabling external DTDs and entities "
    "leaves the application vulnerable to XXE (XML External Entity) attacks."),
   JAVA_SRC,["factory.newDocumentBuilder("],["factory.setFeature(","DISALLOW_DOCTYPE_DECL"],
   ("Explicitly call setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) on "
    "the DocumentBuilderFactory before parsing." + PAD)
)
wr("java","java_deserialization_yaml",RE["deser"],"Deserialization","CWE-502","A08:2021-Software and Data Integrity Failures",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Insecure Deserialization via SnakeYAML",
   ("Deserializing untrusted YAML data using SnakeYAML's Yaml.load() without a strict Constructor "
    "allows arbitrary Java object instantiation, which can lead to RCE."),
   JAVA_SRC,["new Yaml()","yaml.load("],["SafeConstructor"],
   ("Configure SnakeYAML to use a SafeConstructor, which restricts instantiation to basic data types, "
    "preventing the execution of malicious gadget chains." + PAD)
)

# PHP
wr("php","php_weak_crypto_des",RE["crypto"],"Weak Crypto","CWE-327","A02:2021-Cryptographic Failures",
   7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","High","Confirmed",
   "Weak Cryptography: Usage of DES or RC4 in OpenSSL",
   ("Using 'des', 'des-ede3', or 'rc4' cipher methods with openssl_encrypt() relies on obsolete, "
    "insecure cryptography that is vulnerable to modern attacks."),
   [],["openssl_encrypt($data, 'des'","openssl_encrypt($data, 'rc4'"],["openssl_encrypt($data, 'aes-256-gcm'"],
   ("Migrate to strong authenticated encryption such as 'aes-256-gcm' and ensure proper initialization "
    "vectors are used." + PAD)
)
wr("php","php_path_traversal_unlink",RE["pt"],"Path Traversal","CWE-22","A01:2021-Broken Access Control",
   8.1,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H","High","Confirmed",
   "Arbitrary File Deletion via unlink()",
   ("Concatenating user input into a file path passed to unlink() allows a directory traversal "
    "attack that can be used to delete arbitrary sensitive files on the server."),
   PHP_SRC,["unlink("],["basename("],
   ("Strip directory traversal components using basename() and validate that the target file is "
    "within the intended directory." + PAD)
)
wr("php","php_ssti_twig",RE["ssti"],"Code Injection","CWE-94","A03:2021-Injection",
   9.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","Critical","Confirmed",
   "Server-Side Template Injection (SSTI) in Twig",
   ("Creating Twig templates dynamically from unvalidated user input via Twig_Environment::createTemplate "
    "enables SSTI, allowing arbitrary code execution."),
   PHP_SRC,["createTemplate(","render("],["Twig_Environment"],
   ("Do not create templates from user-controlled strings. Use static Twig templates and pass user "
    "input securely via template variables." + PAD)
)
wr("php","php_xxe_simplexml",RE["xxe"],"XXE","CWE-611","A05:2021-Security Misconfiguration",
   8.8,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","High","Confirmed",
   "XXE via simplexml_load_string() or DOMDocument",
   ("Parsing untrusted XML data with simplexml_load_string() or DOMDocument::loadXML() while "
    "libxml_disable_entity_loader(true) is not set (in PHP < 8) allows XXE attacks."),
   PHP_SRC,["simplexml_load_string(","loadXML("],["libxml_disable_entity_loader(true)"],
   ("For PHP < 8.0, call libxml_disable_entity_loader(true) before parsing XML. For PHP 8+, "
    "external entities are disabled by default." + PAD)
)
wr("php","php_redos_preg_match",RE["redos"],"ReDoS","CWE-1333","A01:2021-Broken Access Control",
   5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","Medium","Tentative",
   "ReDoS via preg_match() and complex regex",
   ("Applying a complex regular expression with overlapping quantifiers against untrusted input "
    "using preg_match() can cause catastrophic backtracking and a Denial of Service."),
   PHP_SRC,["preg_match("],["pcre.backtrack_limit"],
   ("Avoid complex regex patterns with nested quantifiers. Enforce strict string length limits and "
    "ensure the pcre.backtrack_limit configuration in php.ini is kept reasonably low." + PAD)
)

print("\nBatch 17: All 40 rules written! 5 per language, diverse CVE domains.")
