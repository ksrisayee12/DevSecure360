from rule_writer import write_rule

PY_SOURCES = [
    "request.args.get(", "request.args[", "request.form.get(", "request.form[",
    "request.json", "request.get_json(", "request.data", "request.values.get(",
    "request.values[", "request.cookies.get(", "request.cookies[",
    "request.headers.get(", "request.headers[", "request.files.get(", "request.stream",
    "request.GET.get(", "request.GET[", "request.POST.get(", "request.POST[",
    "request.body", "request.META.get(", "request.COOKIES.get(", "request.FILES.get(",
    "Query(", "Body(", "Form(", "Path(", "Header(", "Cookie(",
    "os.environ.get(", "os.environ[", "os.getenv(", "sys.argv[", "input("
]

def gen_python_rules():
    # SQLi
    write_rule(
        "python", "python_sqli_raw_sql", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via cursor.execute() with unsanitized user input",
        "User-controlled data from an HTTP request parameter flows directly into cursor.execute() without parameterization. An attacker can inject arbitrary SQL syntax to read sensitive data from any table, modify or delete records, bypass authentication checks, or in some database configurations execute OS commands via xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL).",
        PY_SOURCES,
        ["cursor.execute(", "cursor.executemany(", "connection.execute(", "conn.execute(", "db.execute("],
        ["%s", "?", ":param", "int(", "float("],
        "Replace string concatenation or formatting in SQL queries with parameterized queries. The database driver handles all escaping automatically and the query structure cannot be altered by user input.\n\nUNSAFE:\n  query = \"SELECT * FROM users WHERE name='\" + username + \"'\"\n  cursor.execute(query)\n\nSAFE (psycopg2 / MySQLdb):\n  cursor.execute(\"SELECT * FROM users WHERE name=%s\", (username,))\n\nNever build SQL strings from user input under any circumstances."
    )
    
    # CMDi
    write_rule(
        "python", "python_cmdi_subprocess", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via subprocess or os with shell=True",
        "User input flows directly into OS command execution functions like subprocess.call() or os.system(). If shell=True is used (or implied by os.system), an attacker can use shell metacharacters like ';' or '|' to break out of the intended command and execute arbitrary operating system commands on the server.",
        PY_SOURCES,
        ["subprocess.call(", "subprocess.run(", "subprocess.Popen(", "subprocess.check_output(", "subprocess.check_call(", "os.system(", "os.popen(", "os.execv(", "os.execve(", "os.spawnv(", "commands.getoutput(", "commands.getstatusoutput("],
        ["shlex.quote(", "pipes.quote(", "shlex.split("],
        "Avoid using shell=True and pass arguments as a list of strings rather than a single concatenated string. If you must use a shell, sanitize input strictly using shlex.quote().\n\nUNSAFE:\n  os.system('ping -c 1 ' + user_ip)\n\nSAFE:\n  subprocess.run(['ping', '-c', '1', user_ip], shell=False)"
    )

    # XSS
    write_rule(
        "python", "python_xss_render", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Cross-Site Scripting via render_template_string",
        "User input is passed into template rendering functions like render_template_string or Markup() without being safely escaped. An attacker can inject malicious JavaScript which will be executed in the victim's browser, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of the victim.",
        PY_SOURCES,
        ["render_template_string(", "Markup(", "jinja2.Template(", ".format(", "% operator"],
        ["html.escape(", "markupsafe.escape(", "bleach.clean(", "bleach.linkify(", "cgi.escape("],
        "Never pass user-controlled input directly into render_template_string or wrap it in Markup() without sanitization. Use standard template rendering with autoescape enabled.\n\nUNSAFE:\n  return render_template_string('<h1>Hello ' + request.args.get('name') + '</h1>')\n\nSAFE:\n  return render_template('hello.html', name=request.args.get('name'))"
    )

    # Path Traversal
    write_rule(
        "python", "python_path_traversal", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via open() or os.path.join()",
        "User input dictates file paths passed to functions like open() or send_file(). By injecting directory traversal sequences like '../', an attacker can access files outside the intended directory, potentially exposing sensitive files such as /etc/passwd or application source code.",
        PY_SOURCES,
        ["open(", "os.open(", "os.path.join(", "pathlib.Path(", "io.open(", "builtins.open(", "zipfile.ZipFile(", "tarfile.open(", "shutil.copy(", "shutil.move("],
        ["os.path.basename(", "os.path.abspath(", "pathlib.Path.resolve("],
        "Validate user input to ensure it only represents a filename, not a path. Use os.path.basename() to strip directories, or verify the resolved path starts with the intended base directory.\n\nUNSAFE:\n  with open('/var/www/uploads/' + request.args.get('file')) as f:\n\nSAFE:\n  filename = os.path.basename(request.args.get('file'))\n  with open('/var/www/uploads/' + filename) as f:"
    )

    # SSRF
    write_rule(
        "python", "python_ssrf_requests", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via requests or urllib",
        "User input is used to construct a URL that the server then fetches using libraries like requests, urllib, urllib3, or pycurl. An attacker can force the server to make HTTP requests to arbitrary internal or external domains, potentially accessing internal meta-data services (e.g. AWS IMDS), internal APIs, or bypassing IP allowlists.",
        PY_SOURCES,
        ["requests.get(", "requests.post(", "requests.put(", "requests.delete(", "requests.request(", "requests.Session(", "urllib.request.urlopen(", "urllib.request.urlretrieve(", "urllib.urlopen(", "httplib.HTTPConnection(", "http.client.HTTPConnection(", "aiohttp.ClientSession(", "httpx.get(", "httpx.post(", "httpx.Client(", "urllib3.PoolManager(", "pycurl.Curl("],
        [],
        "Do not allow users to specify arbitrary URLs for the server to fetch. If dynamic URL fetching is required, validate the URL against a strict allowlist of permitted hostnames and protocols.\n\nUNSAFE:\n  response = requests.get(request.args.get('url'))\n\nSAFE:\n  url = request.args.get('url')\n  if url in ['https://api.example.com', 'https://api2.example.com']:\n      response = requests.get(url)"
    )

    # XPath Injection
    write_rule(
        "python", "python_xpath_injection", "XPath Injection", "High", "CWE-643", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "XPath Injection via untrusted input",
        "User input is concatenated directly into an XPath expression. An attacker can alter the query structure to bypass authentication (e.g., matching a true condition) or extract unauthorized XML data.",
        PY_SOURCES,
        [".xpath(", "tree.xpath(", "document.xpath(", "xml.etree.ElementTree.Element.findall(", "xml.etree.ElementTree.Element.find("],
        [],
        "Avoid string concatenation when building XPath queries. Parameterize XPath queries using libraries that support variables (like lxml with dicts of variables).\n\nUNSAFE:\n  tree.xpath(f\"//user[name/text()='{username}']\")\n\nSAFE:\n  tree.xpath(\"//user[name/text()=$username]\", username=username)"
    )

    # SSTI
    write_rule(
        "python", "python_ssti_jinja", "SSTI", "Critical", "CWE-1336", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Server-Side Template Injection via Jinja2/Mako",
        "User input is directly evaluated as a template string by engines like Jinja2 or Mako. An attacker can inject template directives to execute arbitrary Python code on the server, leading to full Remote Code Execution (RCE).",
        PY_SOURCES,
        ["render_template_string(", "jinja2.Template(", "jinja2.Environment(", "mako.template.Template(", "Template(", "string.Template("],
        [],
        "Never pass user input into functions that evaluate template strings (like render_template_string). Always pass user data as context variables to static template files.\n\nUNSAFE:\n  return render_template_string('Hello ' + user_input)\n\nSAFE:\n  return render_template('hello.html', name=user_input)"
    )

    # Deserialization
    write_rule(
        "python", "python_deserialization_pickle", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via pickle or pyyaml",
        "Untrusted data is passed to insecure deserializers like pickle.loads() or yaml.load(). Attackers can craft malicious serialized objects that execute arbitrary Python code when deserialized, leading to complete server compromise.",
        PY_SOURCES,
        ["pickle.loads(", "pickle.load(", "pickle.Unpickler(", "yaml.load(", "marshal.loads(", "shelve.open(", "jsonpickle.decode(", "dill.loads("],
        ["yaml.safe_load(", "json.loads(", "ast.literal_eval("],
        "Do not use pickle, marshal, or yaml.load() for untrusted data. Use safer formats like JSON or use yaml.safe_load().\n\nUNSAFE:\n  data = pickle.loads(request.data)\n\nSAFE:\n  data = json.loads(request.data)"
    )

    # XXE
    write_rule(
        "python", "python_xxe", "XXE", "High", "CWE-611", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "XML External Entity (XXE) Injection via unsafe XML parser",
        "The application parses XML input using an unsafe configuration. An attacker can include external entities in the XML document, leading to local file disclosure, SSRF, or denial of service.",
        PY_SOURCES,
        ["xml.etree.ElementTree.parse(", "lxml.etree.parse(", "xml.sax.parse(", "xml.dom.minidom.parse("],
        ["defusedxml.ElementTree.parse("],
        "Use defusedxml instead of standard XML libraries to parse untrusted XML data.\n\nUNSAFE:\n  import xml.etree.ElementTree as ET\n  ET.parse(request.data)\n\nSAFE:\n  import defusedxml.ElementTree as ET\n  ET.parse(request.data)"
    )

    write_rule(
        "python", "python_csrf", "CSRF", "High", "CWE-352", "A01:2021-Broken Access Control", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "Tentative",
        "Cross-Site Request Forgery via unprotected Flask route without CSRFProtect middleware",
        "The application does not implement CSRF protections. State-changing HTTP handlers (e.g., POST, PUT, DELETE) registered without CSRF protection (like Flask-WTF's CSRFProtect) are vulnerable to cross-site request forgery. Attackers can trick authenticated users into executing unwanted actions. This rule uses heuristic detection.",
        [],
        ["@app.route(", "@app.post(", "@app.put(", "@app.delete(", "@app.patch("],
        ["CSRFProtect", "csrf.protect()", "WTF_CSRF_ENABLED"],
        "Implement CSRF protection by requiring unpredictable tokens on state-changing requests, using established middleware like Flask-WTF. See OWASP Cross-Site Request Forgery Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  app = Flask(__name__)\n\nSAFE:\n  from flask_wtf.csrf import CSRFProtect\n  csrf = CSRFProtect(app)",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/352.html\n# CodeQL Source:   Not applicable — pattern-based rule\n# Semgrep Source:  https://semgrep.dev/r/python.flask.security.wtf-csrf-disabled\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html\n# Verification:    @app.route without CSRFProtect initialization indicates missing CSRF token defense in Flask."
    )

    write_rule(
        "python", "python_jwt_bypass", "JWT Bypass", "Critical", "CWE-287", "A07:2021-Identification and Authentication Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "JWT signature bypass via 'none' algorithm in jwt.decode()",
        "The application decodes JSON Web Tokens (JWT) without explicitly specifying the allowed algorithms or by explicitly permitting the 'none' algorithm. Attackers can forge tokens with the 'none' algorithm to bypass authentication completely.",
        PY_SOURCES,
        ["jwt.decode(", "jose.jwt.decode("],
        [],
        "Always explicitly restrict allowed algorithms when decoding JWTs to prevent the 'none' algorithm attack. See OWASP JSON Web Token Cheat Sheet for complete guidance.\n\nUNSAFE:\n  payload = jwt.decode(token, secret_key)\n  payload = jwt.decode(token, options={\"verify_signature\": False})\n\nSAFE:\n  payload = jwt.decode(token, secret_key, algorithms=[\"HS256\"])",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/287.html\n# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/python/semmle/python/security/dataflow/JwtNoneAlgorithm.qll\n# Semgrep Source:  https://semgrep.dev/r/python.jwt.security.jwt-none-alg\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html\n# Verification:    jwt.decode and jose.jwt.decode without explicit algorithms list are known vulnerabilities in Python JWT libraries."
    )

    write_rule(
        "python", "python_cookie_security", "Cookie Security", "Medium", "CWE-614", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Tentative",
        "Insecure cookie configuration via missing Secure or HttpOnly flags in set_cookie()",
        "A cookie is being set without both the 'Secure' and 'HttpOnly' flags. The 'Secure' flag ensures the cookie is only transmitted over encrypted connections (HTTPS), preventing interception over unencrypted networks. The 'HttpOnly' flag prevents client-side scripts from accessing the cookie, mitigating the risk of cross-site scripting (XSS) attacks stealing session identifiers.",
        [],
        ["set_cookie("],
        ["httponly=True", "secure=True"],
        "Configure cookies with Secure and HttpOnly flags. See OWASP Session Management Cheat Sheet for complete guidance.\n\nUNSAFE:\n  response.set_cookie('session', value)\n\nSAFE:\n  response.set_cookie('session', value, secure=True, httponly=True, samesite='Strict')",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/614.html\n# CodeQL Source:   Not applicable — pattern-based rule\n# Semgrep Source:  https://semgrep.dev/r/python.flask.security.insecure-cookie\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html\n# Verification:    set_cookie without secure=True or httponly=True exposes tokens to interception or XSS."
    )

    write_rule(
        "python", "python_redos", "ReDoS", "High", "CWE-1333", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Regular Expression Denial of Service (ReDoS) via re.compile()",
        "A potentially catastrophic regular expression contains nested quantifiers or overlapping alternatives. If evaluated against a crafted long input string, it can cause the regex engine to backtrack exponentially, consuming all CPU resources and leading to Denial of Service.",
        [],
        ["re.compile(", "re.match(", "re.search(", "re.findall("],
        [],
        "Avoid nested quantifiers like (a+)+ or overlapping alternatives like (a|a)+ in regular expressions. See OWASP Regular Expression Denial of Service Prevention Cheat Sheet for complete guidance.\n\nUNSAFE:\n  pattern = re.compile(r'^(a+)+$')\n\nSAFE:\n  # Use a simpler, non-backtracking regex or limit input length",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/1333.html\n# CodeQL Source:   Not applicable — pattern-based rule\n# Semgrep Source:  https://semgrep.dev/r/python.lang.security.audit.catastrophic-backtracking\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Regular_Expression_Denial_of_Service_Prevention_Cheat_Sheet.html\n# Verification:    re.compile(), re.match(), etc., evaluate regexes and are vulnerable if the pattern string enables catastrophic backtracking."
    )

    # Code Injection
    write_rule(
        "python", "python_code_injection", "Code Injection", "Critical", "CWE-94", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Code Injection via eval() or exec()",
        "User input is passed to eval() or exec(), which executes it as Python code. This allows an attacker to run arbitrary code on the server, resulting in Remote Code Execution.",
        PY_SOURCES,
        ["eval(", "exec(", "compile("],
        ["ast.literal_eval("],
        "Never use eval() or exec() on user input. If you need to parse simple data structures, use ast.literal_eval() or json.loads().\n\nUNSAFE:\n  config = eval(request.args.get('config'))\n\nSAFE:\n  import ast\n  config = ast.literal_eval(request.args.get('config'))"
    )

    # Weak Crypto
    write_rule(
        "python", "python_weak_crypto", "Weak Crypto", "Medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak or Broken Cryptographic Algorithms",
        "The application uses deprecated cryptographic algorithms like MD5, SHA1, or DES. These algorithms are vulnerable to collision attacks or brute forcing, compromising the confidentiality and integrity of protected data.",
        [],
        ["hashlib.md5(", "hashlib.sha1(", "Crypto.Cipher.DES(", "Crypto.Cipher.RC4(", "Crypto.Cipher.Blowfish(", "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES(", "random.random(", "random.randint(", "random.choice("],
        ["hashlib.sha256(", "hashlib.sha512(", "hashlib.sha3_256(", "secrets.token_bytes(", "secrets.token_hex(", "os.urandom("],
        "Use modern, strong cryptographic algorithms like AES-GCM and SHA-256. For secure random number generation, use the secrets module instead of the random module.\n\nUNSAFE:\n  hash = hashlib.md5(data.encode()).hexdigest()\n\nSAFE:\n  hash = hashlib.sha256(data.encode()).hexdigest()"
    )
    
    # Hardcoded Secret
    write_rule(
        "python", "python_hardcoded_secret", "Hardcoded Secret", "High", "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Hardcoded Secret or Credential",
        "The application contains hardcoded secrets (API keys, passwords, tokens) in the source code. If the code is leaked or accessed by unauthorized individuals, the secrets can be extracted and abused.",
        [],
        [],
        [],
        "Remove hardcoded secrets from source code. Load credentials dynamically from environment variables, configuration files securely provisioned at runtime, or a secrets management system.\n\nUNSAFE:\n  API_KEY = 'sk-12345abcdef'\n\nSAFE:\n  API_KEY = os.environ.get('API_KEY')"
    )
    
    # Log Injection
    write_rule(
        "python", "python_log_injection", "Log Injection", "Medium", "CWE-117", "A09:2021-Security Logging and Monitoring Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Confirmed",
        "Log Injection via logging module",
        "User input is directly written to log files without sanitization. An attacker can forge log entries, inject CRLF characters to manipulate log structure, or hide malicious activities.",
        PY_SOURCES,
        ["logging.debug(", "logging.info(", "logging.warning(", "logging.error(", "logging.critical(", "logging.log(", "log.info(", "log.error("],
        [],
        "Sanitize user input before logging it, particularly by stripping newline characters (CR/LF) and encoding special characters, or use structured logging (JSON) to separate data from log metadata.\n\nUNSAFE:\n  logging.info('User failed login: ' + username)\n\nSAFE:\n  logging.info('User failed login: %s', username.replace('\\n', ''))"
    )
    
    # NoSQLi
    write_rule(
        "python", "python_nosqli", "NoSQLi", "High", "CWE-943", "A03:2021-Injection", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "Confirmed",
        "NoSQL Injection via MongoDB query operators",
        "User input is used to dynamically construct NoSQL queries. An attacker can inject query operators (like $ne or $gt) to alter the query logic, bypass authentication, or extract data.",
        PY_SOURCES,
        ["db.find(", "db.find_one(", "db.find_one_and_update(", "collection.find(", "collection.aggregate(", "pymongo.collection.find(", "$where", "$regex", "motor.collection.find("],
        [],
        "Ensure user input is properly typed (e.g., cast to string) before passing it into NoSQL queries to prevent operator injection.\n\nUNSAFE:\n  db.users.find({'username': request.json.get('username')})\n\nSAFE:\n  db.users.find({'username': str(request.json.get('username'))})"
    )

    # LDAP Injection
    write_rule(
        "python", "python_ldap_injection", "LDAP Injection", "High", "CWE-90", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "LDAP Injection via ldap module",
        "User input is used to dynamically construct LDAP search filters. An attacker can inject special characters to bypass authentication or extract unauthorized information from the directory.",
        PY_SOURCES,
        ["ldap.search(", "ldap3.Connection.search(", "ldap.modify(", "ldap.add(", "ldap.delete(", "ldap.search_s(", "ldap.compare("],
        [],
        "Escape LDAP special characters (*, (, ), \\, \x00) using a library function before including user input in LDAP queries.\n\nUNSAFE:\n  conn.search('dc=example,dc=com', f'(uid={username})')\n\nSAFE:\n  import ldap3.utils.conv\n  safe_username = ldap3.utils.conv.escape_filter_chars(username)\n  conn.search('dc=example,dc=com', f'(uid={safe_username})')"
    )

    # Open Redirect
    write_rule(
        "python", "python_open_redirect", "Open Redirect", "Medium", "CWE-601", "A01:2021-Broken Access Control", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "Open Redirect via redirect/Location",
        "User input is used to construct a redirect URL without validation. An attacker can craft a link that redirects a user to a malicious site, facilitating phishing attacks.",
        PY_SOURCES,
        ["redirect(", "flask.redirect(", "HttpResponseRedirect(", "django.shortcuts.redirect("],
        [],
        "Validate the redirect URL against an allowlist, or ensure it is a relative path rather than an absolute URL to an external domain.\n\nUNSAFE:\n  return redirect(request.args.get('next'))\n\nSAFE:\n  next_url = request.args.get('next')\n  if next_url.startswith('/') and not next_url.startswith('//'):\n      return redirect(next_url)"
    )

    # File Upload
    write_rule(
        "python", "python_file_upload", "File Upload", "High", "CWE-434", "A04:2021-Insecure Design", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Unrestricted Upload of File with Dangerous Type",
        "The application allows users to upload files but does not adequately validate the file extension or type. An attacker could upload an executable file (like a .py or .php script) and execute arbitrary code.",
        PY_SOURCES,
        ["request.files.get(", "file.save("],
        ["secure_filename("],
        "Ensure uploaded files have a verified safe extension and are stored outside the web root or with randomized names. Use werkzeug.utils.secure_filename.\n\nUNSAFE:\n  file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))\n\nSAFE:\n  from werkzeug.utils import secure_filename\n  filename = secure_filename(file.filename)\n  file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/434.html\n# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/python/semmle/python/security/dataflow/ArbitraryFileWrite.qll\n# Semgrep Source:  https://semgrep.dev/r/python.flask.security.audit.upload-file.upload-file\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html\n# Verification:    request.files and file.save() are standard Flask patterns for receiving and saving files without inherent type validation."
    )

    # Mass Assignment
    write_rule(
        "python", "python_mass_assignment", "Mass Assignment", "Medium", "CWE-915", "A08:2021-Software and Data Integrity Failures", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "Confirmed",
        "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "The application takes a JSON or dictionary payload from the user and directly maps it to internal object attributes. An attacker can set unauthorized properties, such as granting themselves admin privileges.",
        PY_SOURCES,
        ["Model(**", "obj.__dict__.update(", "setattr("],
        [],
        "Do not bind raw user input dictionaries directly to objects. Use explicitly defined data transfer objects (DTOs) or whitelist the fields that can be modified.\n\nUNSAFE:\n  user.update(**request.json)\n\nSAFE:\n  user.email = request.json.get('email')"
    )

    # CORS Misconfiguration
    write_rule(
        "python", "python_cors_misconfiguration", "Misconfiguration", "Medium", "CWE-942", "A05:2021-Security Misconfiguration", 5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "Confirmed",
        "Permissive Cross-Origin Resource Sharing (CORS)",
        "The application configures CORS to allow requests from any origin ('*') along with credentials. This allows malicious sites to read sensitive data across origins.",
        [],
        ["CORS(app, origins=\"*\")", "CORS(app, resources={r\"/*\": {\"origins\": \"*\"}})", "flask_cors.CORS("],
        [],
        "Configure CORS to only allow trusted domains, never use the wildcard '*' origin when credentials are required.\n\nUNSAFE:\n  CORS(app, origins='*')\n\nSAFE:\n  CORS(app, origins=['https://trusted.example.com'])",
        evidence="# RESEARCH EVIDENCE\n# CWE Source:      https://cwe.mitre.org/data/definitions/942.html\n# CodeQL Source:   Not applicable — pattern-based rule\n# Semgrep Source:  https://semgrep.dev/r/python.flask.security.cors-wildcard.cors-wildcard\n# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html\n# Verification:    flask_cors.CORS with origins='*' enables globally permissive cross-origin requests."
    )

    # Batch 4: SQLi Variants
    write_rule(
        "python", "python_sqli_sqlalchemy", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in SQLAlchemy",
        "User input is directly concatenated into a raw SQL query executed via SQLAlchemy. An attacker can manipulate the query to extract sensitive data or modify the database.",
        PY_SOURCES,
        ["db.session.execute(text(", "engine.execute(", ".filter(text("],
        [],
        "Always use SQLAlchemy's built-in parameterized queries using text('... :param').bindparams(param=value) instead of string formatting or concatenation.\n\nUNSAFE:\n  db.session.execute(text(f'SELECT * FROM users WHERE id={user_id}'))\n\nSAFE:\n  db.session.execute(text('SELECT * FROM users WHERE id=:id'), {'id': user_id})"
    )

    write_rule(
        "python", "python_sqli_django", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in Django ORM",
        "Raw SQL queries are constructed using string formatting and passed to Django's ORM raw(), extra(), or cursor.execute().",
        PY_SOURCES,
        [".extra(", ".raw(", "RawSQL(", "cursor.execute("],
        [],
        "Use Django ORM's standard queryset filtering methods. If raw SQL is unavoidable, always pass user input via the `params` argument.\n\nUNSAFE:\n  User.objects.raw(f'SELECT * FROM auth_user WHERE username=\"{username}\"')\n\nSAFE:\n  User.objects.raw('SELECT * FROM auth_user WHERE username=%s', [username])"
    )

    write_rule(
        "python", "python_sqli_asyncpg", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in asyncpg",
        "User input is interpolated directly into SQL queries executed with asyncpg, risking SQL injection.",
        PY_SOURCES,
        ["conn.execute(", "conn.fetch(", "conn.fetchrow("],
        [],
        "Use asyncpg's positional parameters ($1, $2, etc.) to pass variables securely.\n\nUNSAFE:\n  await conn.fetch(f'SELECT * FROM users WHERE name={name}')\n\nSAFE:\n  await conn.fetch('SELECT * FROM users WHERE name=$1', name)"
    )

    write_rule(
        "python", "python_sqli_pymysql", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in pymysql",
        "User input is concatenated into SQL queries and executed via PyMySQL cursor.execute().",
        PY_SOURCES,
        ["cursor.execute(f", "cursor.execute(\"{}\""],
        [],
        "Always pass user input as a tuple of arguments to cursor.execute() instead of formatting the SQL string directly.\n\nUNSAFE:\n  cursor.execute(f\"SELECT * FROM data WHERE id={id}\")\n\nSAFE:\n  cursor.execute(\"SELECT * FROM data WHERE id=%s\", (id,))"
    )

    # Batch 4: CMDi Variants
    write_rule(
        "python", "python_cmdi_os_system", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via os.system",
        "Untrusted input is passed to os.system(). Since os.system always executes via the shell, this is highly vulnerable to command injection.",
        PY_SOURCES,
        ["os.system("],
        [],
        "Avoid os.system(). Use the subprocess module with shell=False and pass arguments as a list.\n\nUNSAFE:\n  os.system(f'ping -c 1 {ip}')\n\nSAFE:\n  subprocess.run(['ping', '-c', '1', ip])"
    )

    write_rule(
        "python", "python_cmdi_popen", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via os.popen",
        "Untrusted input is passed to os.popen(). Like os.system, os.popen executes via the shell and is vulnerable to injection.",
        PY_SOURCES,
        ["os.popen("],
        [],
        "Do not use os.popen(). Use subprocess.Popen or subprocess.run with shell=False.\n\nUNSAFE:\n  os.popen('ls ' + user_dir)\n\nSAFE:\n  subprocess.run(['ls', user_dir], capture_output=True)"
    )

    write_rule(
        "python", "python_cmdi_execv", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via os.exec* variants",
        "User input controls the executable path or arguments in os.execv, os.execve, os.execvp, or os.execvpe.",
        PY_SOURCES,
        ["os.execv(", "os.execve(", "os.execvp(", "os.execvpe("],
        [],
        "Ensure the executable path is strictly validated against an allowlist. Avoid letting users control the program being executed."
    )

    write_rule(
        "python", "python_cmdi_asyncio", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via asyncio subprocess",
        "Untrusted input is used in asyncio.create_subprocess_shell() or manipulated asynchronously.",
        PY_SOURCES,
        ["asyncio.create_subprocess_shell(", "asyncio.create_subprocess_exec("],
        [],
        "Use asyncio.create_subprocess_exec() instead of shell(), and ensure arguments are passed safely as a list, never concatenated as strings."
    )

    # Batch 4: Path Traversal Variants
    write_rule(
        "python", "python_path_traversal_send", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via Flask send_file",
        "User input controls the file path passed to flask.send_file() or send_from_directory(), allowing attackers to download arbitrary files from the server.",
        PY_SOURCES,
        ["flask.send_file(", "send_from_directory(", "send_file("],
        ["werkzeug.utils.safe_join("],
        "Always use werkzeug.utils.safe_join() or validate the requested filename against a strict allowlist or a base directory. Never trust user-provided paths."
    )

    write_rule(
        "python", "python_path_traversal_zip", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Confirmed",
        "Path Traversal via zipfile (Zip Slip)",
        "Extracting files from an untrusted ZIP archive using extractall() without validating the file paths inside the archive.",
        PY_SOURCES,
        ["zipfile.ZipFile(", "ZipFile.extract(", "ZipFile.extractall("],
        [],
        "Iterate over archive entries and validate that their absolute path starts with the intended target directory before extracting them."
    )

    write_rule(
        "python", "python_path_traversal_tar", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Confirmed",
        "Path Traversal via tarfile (Tar Slip)",
        "Extracting files from an untrusted TAR archive using extractall() without validating paths.",
        PY_SOURCES,
        ["tarfile.open(", "TarFile.extract(", "TarFile.extractall("],
        ["filter='data'"],
        "In Python 3.11.4+, use the `filter='data'` argument in tarfile.extractall(). On older versions, manually validate that the destination path is within the target directory."
    )

    write_rule(
        "python", "python_path_traversal_shutil", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Confirmed",
        "Path Traversal via shutil operations",
        "User input controls the source or destination path in shutil.copy, shutil.move, or related functions.",
        PY_SOURCES,
        ["shutil.copy(", "shutil.copy2(", "shutil.move(", "shutil.copyfile("],
        [],
        "Validate paths securely using os.path.abspath and os.path.commonpath to ensure they fall within an authorized base directory before performing file operations."
    )

    # Batch 4: SSRF Variants
    write_rule(
        "python", "python_ssrf_urllib3", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via urllib3",
        "Untrusted input is used to construct a URL that the application requests using urllib3.",
        PY_SOURCES,
        ["urllib3.PoolManager(", "PoolManager.request("],
        [],
        "Validate the target URL against an allowlist of approved hostnames or IP addresses before making the request."
    )

    write_rule(
        "python", "python_ssrf_aiohttp", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via aiohttp",
        "Untrusted input controls the URL passed to aiohttp.ClientSession get() or post() methods.",
        PY_SOURCES,
        ["aiohttp.ClientSession(", "session.get(", "session.post("],
        [],
        "Ensure the URL domain and scheme are validated before issuing the HTTP request to prevent unauthorized internal network access."
    )

    write_rule(
        "python", "python_ssrf_httpx", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "Confirmed",
        "Server-Side Request Forgery via httpx",
        "User input is passed to httpx request functions without validation, enabling Server-Side Request Forgery (SSRF) attacks against internal resources.",
        PY_SOURCES,
        ["httpx.get(", "httpx.post(", "httpx.Client(", "httpx.AsyncClient("],
        [],
        "Strictly validate the target URL. Consider implementing network-level egress filtering to prevent internal network scanning."
    )

    # Batch 4: Deserialization Variants
    write_rule(
        "python", "python_deser_yaml", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via yaml.load",
        "The application deserializes YAML data using yaml.load() without specifying yaml.SafeLoader, which allows the execution of arbitrary Python code.",
        PY_SOURCES,
        ["yaml.load("],
        ["Loader=yaml.SafeLoader", "yaml.safe_load("],
        "Always use yaml.safe_load() or specify Loader=yaml.SafeLoader when parsing untrusted YAML data to prevent arbitrary code execution."
    )

    write_rule(
        "python", "python_deser_dill", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via dill",
        "Untrusted data is deserialized using dill.loads() or dill.load(), which can execute arbitrary code upon unpickling.",
        PY_SOURCES,
        ["dill.loads(", "dill.load("],
        [],
        "Do not use dill to deserialize untrusted data. Use a safe format like JSON (via json.loads) for data exchange."
    )

    write_rule(
        "python", "python_deser_marshal", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via marshal",
        "Untrusted data is deserialized using marshal.loads(), which is explicitly documented as insecure and can crash the interpreter or execute code.",
        PY_SOURCES,
        ["marshal.loads(", "marshal.load("],
        [],
        "The marshal module is not intended to be secure against erroneous or maliciously constructed data. Never use it for untrusted data."
    )

    # Batch 4: Weak Crypto Variants
    write_rule(
        "python", "python_weak_crypto_pycrypto", "Weak Crypto", "High", "CWE-328", "A02:2021-Cryptographic Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Weak Block/Stream Ciphers (PyCrypto/PyCryptodome)",
        "The application uses weak ciphers like DES, ARC4, or Blowfish, which are vulnerable to modern cryptanalysis.",
        [],
        ["Crypto.Cipher.DES(", "Crypto.Cipher.ARC4(", "Crypto.Cipher.Blowfish("],
        [],
        "Replace weak ciphers with AES (Advanced Encryption Standard) in authenticated modes like GCM to ensure cryptographic security."
    )

    write_rule(
        "python", "python_weak_crypto_ecb", "Weak Crypto", "High", "CWE-327", "A02:2021-Cryptographic Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of Insecure AES ECB Mode",
        "AES is used in Electronic Codebook (ECB) mode, which does not provide serious message confidentiality because it encrypts identical plaintext blocks into identical ciphertext blocks.",
        [],
        ["AES.MODE_ECB"],
        [],
        "Never use ECB mode for cryptographic operations. Use authenticated encryption modes such as AES-GCM (AES.MODE_GCM) instead."
    )

    write_rule(
        "python", "python_weak_crypto_rsa_small", "Weak Crypto", "High", "CWE-326", "A02:2021-Cryptographic Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Inadequate RSA Key Size",
        "The application generates RSA keys with insufficient sizes (e.g., 512 or 1024 bits), which can be factored by well-resourced attackers.",
        [],
        ["RSA.generate(512)", "RSA.generate(1024)"],
        [],
        "Use an RSA key size of at least 2048 bits. 3072 or 4096 bits are recommended for long-term security."
    )

    write_rule(
        "python", "python_weak_crypto_md5pwd", "Weak Crypto", "High", "CWE-916", "A02:2021-Cryptographic Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Use of MD5/SHA1 for Password Hashing",
        "Passwords or sensitive secrets are hashed using fast, unkeyed hash functions like MD5 or SHA1 without salting, making them easily crackable.",
        [],
        ["hashlib.md5(password", "hashlib.sha1(password"],
        [],
        "Do not use MD5 or SHA1 for passwords. Use a robust, slow hashing algorithm like Argon2, bcrypt, scrypt, or PBKDF2."
    )

    # Batch 4: Hardcoded Secret Variants
    write_rule(
        "python", "python_secret_generic", "Hardcoded Secret", "High", "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Generic Hardcoded Secret (Password/API Key)",
        "A variable explicitly named password, secret, api_key, or token is assigned a hardcoded string literal.",
        [],
        ["password=\"", "password='", "secret=\"", "secret='", "api_key=\"", "api_key='", "token=\"", "token='"],
        [],
        "Load generic secrets securely from environment variables, configuration files, or a dedicated secrets manager instead of hardcoding them."
    )

    write_rule(
        "python", "python_secret_aws", "Hardcoded Secret", "Critical", "CWE-798", "A07:2021-Identification and Authentication Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Hardcoded AWS Credentials",
        "AWS access keys or secret access keys are hardcoded into the source code. This can lead to complete cloud environment compromise if leaked.",
        [],
        ["aws_access_key_id=\"", "aws_secret_access_key=\"", "aws_access_key_id='", "aws_secret_access_key='"],
        [],
        "Never hardcode AWS credentials. Use IAM roles, the ~/.aws/credentials file, or load them from environment variables."
    )

    write_rule(
        "python", "python_secret_private_key", "Hardcoded Secret", "Critical", "CWE-798", "A07:2021-Identification and Authentication Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Hardcoded Private Key",
        "An RSA or generic private key PEM block is hardcoded directly in the source file.",
        [],
        ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"],
        [],
        "Store private keys securely in key vaults or properly protected configuration files. Do not embed private key material in application code."
    )

    write_rule(
        "python", "python_secret_connection_str", "Hardcoded Secret", "High", "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Hardcoded Database Connection String with Credentials",
        "A database connection string (e.g., SQLAlchemy or psycopg2) containing a password is hardcoded.",
        [],
        ["://root:", "://admin:", "://postgres:", "://sa:"],
        ["mysql+pymysql", "postgresql", "mssql+pyodbc"],
        "Do not embed database passwords in connection strings within the code. Load the connection URI dynamically at runtime from secure storage."
    )

if __name__ == '__main__':
    gen_python_rules()
