# DevSecure360 SAST Engine — Rule Correction + Phased Expansion to 1,000+ Rules
# READ THIS ENTIRE DOCUMENT BEFORE TOUCHING ANY FILE.
# This prompt is structured in phases. Complete them in exact order.

---

## CURRENT STATE (as of this audit)

```
Total rules:  151 across 8 languages
Errors:       3 confirmed bugs still unfixed from previous review
Warnings:     85 files missing research evidence comments
Target:       1,000 - 1,500 rules
```

Current coverage per language:
```
Python:     28 rules | 26 vuln classes covered
JavaScript: 20 rules | 18 vuln classes covered
Java:       24 rules | 20 vuln classes covered
PHP:        21 rules | 18 vuln classes covered
Go:         16 rules | 13 vuln classes covered
C#:         23 rules | 19 vuln classes covered
C:           9 rules |  8 vuln classes covered
C++:        10 rules |  8 vuln classes covered
```

---

## PHASE 0 — FIX 3 REMAINING BUGS FIRST

Do this before any expansion. These are confirmed bugs from the last audit.
Do not create any new files until all three are fixed.

### Fix 1 — `rules/javascript/js_cookie_security.yaml`
```yaml
# CHANGE THIS:
confidence: Confirmed

# TO THIS:
confidence: Tentative
```

### Fix 2 — All `Type Confusion` vuln_class values
Find every file with `vuln_class: Type Confusion` and change it to `vuln_class: Code Injection`.
Files confirmed to have this: `python_insecure_reflection.yaml`, `java_insecure_reflection.yaml`,
`php_insecure_reflection.yaml`, `csharp_insecure_reflection.yaml`.
Check all other languages too. `Type Confusion` is a C/C++ memory corruption concept (CWE-843).
Using it for reflection-based code execution is wrong. The correct class is `Code Injection`.

### Fix 3 — All `Log Forging` vuln_class values
Find every file with `vuln_class: Log Forging` and change it to `vuln_class: Log Injection`.
Files confirmed to have this: `js_log_injection.yaml`, `go_log_injection.yaml`,
`php_log_injection.yaml`, `csharp_log_injection.yaml`.
`Log Forging` is not in the allowed list. `Log Injection` is.

### Verify Phase 0
Run this before proceeding to Phase 1:
```python
python3 << 'EOF'
import yaml
from pathlib import Path
errors = []
for f in Path("rules").rglob("*.yaml"):
    r = yaml.safe_load(f.read_text(encoding="utf-8"))
    if not r: continue
    vc = str(r.get("vuln_class","")).strip()
    if vc in ("Type Confusion", "Log Forging"):
        errors.append(f"WRONG vuln_class '{vc}': {f.name}")
    rid = str(r.get("rule_id","")).strip()
    if rid == "js_cookie_security" and r.get("confidence") != "Tentative":
        errors.append(f"WRONG confidence in {f.name}")
if errors:
    [print(f"ERROR: {e}") for e in errors]
else:
    print("PHASE 0 COMPLETE — 0 errors")
EOF
```
Do not proceed until output is `PHASE 0 COMPLETE — 0 errors`.

---

## PHASE 1 — MANDATORY RESEARCH METHODOLOGY

Every single new rule from this point forward must follow this process.
No exceptions. No skipping steps.

### Step 1 — Look up the CWE
URL: `https://cwe.mitre.org/data/definitions/{NUMBER}.html`
Read the official description. Confirm:
- The vulnerability class name matches the CWE title
- The languages listed are correct
- The consequence matches the severity you will assign

### Step 2 — Find sinks in CodeQL or Semgrep
Use one of:
- `https://codeql.github.com/codeql-standard-libraries/{language}/`
- `https://semgrep.dev/r` — search by language and vuln class
- `https://github.com/github/codeql` — browse the QL files for the language

Read the actual source code of the rule. Copy the exact function names they use as sinks.
These are verified by professional security engineers.

### Step 3 — Find sources in official framework docs
- Flask: `https://flask.palletsprojects.com/en/latest/api/#flask.Request`
- Django: `https://docs.djangoproject.com/en/stable/ref/request-response/`
- Express: `https://expressjs.com/en/api.html#req`
- Spring: `https://docs.spring.io/spring-framework/docs/current/javadoc-api/`
- Gin: `https://pkg.go.dev/github.com/gin-gonic/gin`
- ASP.NET: `https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.httprequest`

### Step 4 — Find sanitizers in OWASP Cheat Sheets
URL: `https://cheatsheetseries.owasp.org/`
The OWASP Cheat Sheet Series has verified sanitizers for every major vuln class.
Use their exact function names and patterns.

### Step 5 — Record evidence in every new file
Every new YAML file must start with this comment block:
```yaml
# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/{NUMBER}.html
# CodeQL Source:   {URL} or "Not applicable — pattern-based rule"
# Semgrep Source:  {URL} or "Not applicable — pattern-based rule"
# OWASP Cheat:     {URL}
# Verification:    {One sentence confirming each sink is real and from which source}
```

If you cannot fill in the CodeQL or Semgrep URL with a real link, the sink is not verified.
Do not write unverified sinks.

---

## PHASE 2 — BATCH EXECUTION PLAN

Rules are added in batches of exactly 30 per run.
Each batch targets one specific expansion type.
Quality over quantity — 30 accurate rules beats 300 fabricated ones.

After each batch: run the validator. Fix all errors before starting the next batch.

---

## COMPLETE EXPANSION ROADMAP

This is the full plan from 151 to 1,000+ rules, in batch order.

### BATCH 1 (30 rules) — Fill Missing Vuln Classes: Python + JavaScript
Fill these confirmed gaps with one rule per missing class:

**Python — 9 missing classes:**
```
python_file_upload           → vuln_class: File Upload        → CWE-434
python_mass_assignment       → vuln_class: Mass Assignment    → CWE-915
python_cors_misconfiguration → vuln_class: Misconfiguration   → CWE-942
```

**JavaScript — 11 missing classes:**
```
js_xxe                       → vuln_class: XXE                → CWE-611
js_ldap_injection            → vuln_class: LDAP Injection     → CWE-90
js_hardcoded_secret          → vuln_class: Hardcoded Secret   → CWE-798
js_log_injection             → vuln_class: Log Injection      → CWE-117
js_race_condition            → vuln_class: Race Condition     → CWE-362
js_cleartext_transmission    → vuln_class: Cleartext Transmission → CWE-319
js_info_exposure             → vuln_class: Information Exposure   → CWE-209
js_cors_misconfiguration     → vuln_class: Misconfiguration   → CWE-942
js_mass_assignment           → vuln_class: Mass Assignment    → CWE-915
js_file_upload               → vuln_class: File Upload        → CWE-434
js_misconfiguration          → vuln_class: Misconfiguration   → CWE-16
```

**Research links for Batch 1:**
- File Upload (CWE-434): `https://cwe.mitre.org/data/definitions/434.html`
  Semgrep: `https://semgrep.dev/r/python.flask.security.file-upload`
  Python sinks: `request.files.get(`, `file.save(`, `werkzeug.utils.secure_filename(`
- Mass Assignment (CWE-915): `https://cwe.mitre.org/data/definitions/915.html`
  Semgrep: `https://semgrep.dev/r/python.flask.security.mass-assignment`
  Python sinks: `Model(**request.json)`, `obj.__dict__.update(`, `setattr(obj, key, val)`
- CORS (CWE-942): `https://cwe.mitre.org/data/definitions/942.html`
  Semgrep: `https://semgrep.dev/r/python.flask-cors.security.wildcard-cors`
  Python sinks: `CORS(app, origins="*")`, `after_request` with `Access-Control-Allow-Origin: *`
- JS XXE: Node.js uses `libxmljs`, `xml2js`, `fast-xml-parser` — research their entity config
- JS LDAP: `ldapjs` library — `client.search(`, `client.add(`, `client.modify(`
- JS Hardcoded Secret: Pattern-based — variable names matching secret patterns + string literals
- JS CORS: `res.header("Access-Control-Allow-Origin", "*")`, `cors({origin: "*"})`

### BATCH 2 (30 rules) — Fill Missing Vuln Classes: Java + PHP

**Java — 8 missing classes:**
```
java_nosqli                  → vuln_class: NoSQLi             → CWE-943
java_csrf                    → vuln_class: CSRF               → CWE-352
java_jwt_bypass              → vuln_class: JWT Bypass         → CWE-287
java_cookie_security         → vuln_class: Cookie Security    → CWE-614
java_redos                   → vuln_class: ReDoS              → CWE-1333
java_mass_assignment         → vuln_class: Mass Assignment    → CWE-915
java_cors_misconfiguration   → vuln_class: Misconfiguration   → CWE-942
```

**PHP — 11 missing classes:**
```
php_nosqli                   → vuln_class: NoSQLi             → CWE-943
php_log_injection            → vuln_class: Log Injection      → CWE-117
php_hardcoded_secret         → vuln_class: Hardcoded Secret   → CWE-798
php_csrf                     → vuln_class: CSRF               → CWE-352
php_jwt_bypass               → vuln_class: JWT Bypass         → CWE-287
php_cookie_security          → vuln_class: Cookie Security    → CWE-614
php_redos                    → vuln_class: ReDoS              → CWE-1333
php_cleartext_transmission   → vuln_class: Cleartext Transmission → CWE-319
php_info_exposure            → vuln_class: Information Exposure   → CWE-209
php_misconfiguration         → vuln_class: Misconfiguration   → CWE-16
php_cors_misconfiguration    → vuln_class: Misconfiguration   → CWE-942
```

**Research links for Batch 2:**
- Java NoSQLi: Spring Data MongoDB — `MongoTemplate.find(`, `mongoOps.findOne(`
  CodeQL: `https://codeql.github.com/codeql-standard-libraries/java/` — search NoSQLi
- Java CSRF: Spring Security — `csrf().disable()` pattern
  Semgrep: `https://semgrep.dev/r/java.spring.security.csrf-disabled`
- Java JWT: `com.auth0.jwt.JWT.require(` without algorithm — verify via auth0 docs
- PHP CSRF: WordPress `wp_nonce_field`, Laravel `@csrf` — detect absence
- PHP JWT: `firebase/php-jwt` library — `JWT::decode(` without algorithm specification
- PHP Cookie: `setcookie(` without `httponly` and `secure` flags

### BATCH 3 (30 rules) — Fill Missing Vuln Classes: Go + C# + C + C++

**Go — 13 missing classes:**
```
go_nosqli                    → vuln_class: NoSQLi             → CWE-943
go_xxe                       → Research first — may not apply
go_deserialization           → vuln_class: Deserialization    → CWE-502
go_xpath_injection           → vuln_class: XPath Injection    → CWE-643
go_code_injection            → vuln_class: Code Injection     → CWE-94
go_jwt_bypass                → vuln_class: JWT Bypass         → CWE-287
go_cookie_security           → vuln_class: Cookie Security    → CWE-614
go_redos                     → vuln_class: ReDoS              → CWE-1333
go_race_condition            → vuln_class: Race Condition     → CWE-362
go_info_exposure             → vuln_class: Information Exposure → CWE-209
go_cors_misconfiguration     → vuln_class: Misconfiguration   → CWE-942
go_prototype_pollution       → Research first — may not apply in Go
```

**C# — 8 missing classes:**
```
csharp_nosqli                → vuln_class: NoSQLi             → CWE-943
csharp_log_injection         → vuln_class: Log Injection      → CWE-117
csharp_hardcoded_secret      → vuln_class: Hardcoded Secret   → CWE-798
csharp_csrf                  → vuln_class: CSRF               → CWE-352
csharp_jwt_bypass            → vuln_class: JWT Bypass         → CWE-287
csharp_cookie_security       → vuln_class: Cookie Security    → CWE-614
csharp_redos                 → vuln_class: ReDoS              → CWE-1333
csharp_cors_misconfiguration → vuln_class: Misconfiguration   → CWE-942
```

**C — 2 missing classes:**
```
c_race_condition             → vuln_class: Race Condition     → CWE-362
c_null_pointer               → vuln_class: Null Pointer Dereference → CWE-476
```

**C++ — 6 missing classes:**
```
cpp_use_after_free           → vuln_class: Use After Free     → CWE-416
cpp_race_condition           → vuln_class: Race Condition     → CWE-362
cpp_null_pointer             → vuln_class: Null Pointer Dereference → CWE-476
cpp_out_of_bounds_read       → vuln_class: Out-of-bounds Read → CWE-125
cpp_misconfiguration         → vuln_class: Misconfiguration   → CWE-1188
```

**IMPORTANT — Research before writing Go and C++ rules:**
- Go Prototype Pollution: Go is strongly typed with no prototype chain. This vuln class does NOT apply to Go. Write a note file `go_prototype_pollution_NOT_APPLICABLE.md` instead of a YAML file, explaining why.
- Go XXE: Research whether `encoding/xml` processes external entities in Go 1.21+. If not, write a note file instead.
- C++ SSRF: C++ does not have a standard HTTP library. Only libcurl is widely used. Only write this if `curl_easy_setopt` with `CURLOPT_URL` is detected in the codebase.

### BATCH 4 (30 rules) — Framework-Specific Python SQLi + CMDi Depth

Each existing Python rule covers only one sink family.
These batches go deeper — one rule per framework or library.

**Python SQLi variants (4 new rules):**
```
python_sqli_sqlalchemy       → SQLAlchemy: db.session.execute(text(, engine.execute(, .filter(
python_sqli_django           → Django ORM: .extra(, .raw(, RawSQL(, cursor.execute(
python_sqli_asyncpg          → asyncpg: conn.execute(, conn.fetch(, conn.fetchrow(
python_sqli_pymysql          → pymysql: cursor.execute( with string concat
```

Research: `https://docs.sqlalchemy.org/en/14/core/connections.html#sqlalchemy.engine.Connection.execute`
Research: `https://docs.djangoproject.com/en/stable/topics/db/sql/`
Research: `https://magicstack.github.io/asyncpg/current/api/`

**Python CMDi variants (4 new rules):**
```
python_cmdi_os_system        → os.system( specifically — always shell, no arg list option
python_cmdi_popen            → os.popen( — returns file object, shell always true
python_cmdi_execv            → os.execv(, os.execve(, os.execvp(, os.execvpe(
python_cmdi_asyncio          → asyncio.create_subprocess_shell(, asyncio.create_subprocess_exec(
```

**Python Path Traversal variants (4 new rules):**
```
python_path_traversal_send   → flask.send_file(, send_from_directory(
python_path_traversal_zip    → zipfile.ZipFile(, ZipFile.extract(, ZipFile.extractall(
python_path_traversal_tar    → tarfile.open(, TarFile.extract(, TarFile.extractall(
python_path_traversal_shutil → shutil.copy(, shutil.copy2(, shutil.move(, shutil.copyfile(
```

**Python SSRF variants (3 new rules):**
```
python_ssrf_urllib3          → urllib3.PoolManager(, PoolManager.request(
python_ssrf_aiohttp          → aiohttp.ClientSession(, session.get(, session.post(
python_ssrf_httpx            → httpx.get(, httpx.post(, httpx.Client(, httpx.AsyncClient(
```

**Python Deserialization variants (3 new rules):**
```
python_deser_yaml            → yaml.load( without Loader=yaml.SafeLoader
python_deser_dill            → dill.loads(, dill.load(
python_deser_marshal         → marshal.loads(, marshal.load(
```

**Python Weak Crypto variants (4 new rules):**
```
python_weak_crypto_pycrypto  → Crypto.Cipher.DES(, Crypto.Cipher.ARC4(, Crypto.Cipher.Blowfish(
python_weak_crypto_ecb       → AES.new(key, AES.MODE_ECB) — ECB mode is insecure
python_weak_crypto_rsa_small → RSA.generate(512), RSA.generate(1024) — key too small
python_weak_crypto_md5pwd    → hashlib.md5( when in password context
```

**Python Hardcoded Secret variants (4 new rules):**
```
python_secret_generic        → password=", secret=", api_key=", token=" with string literal
python_secret_aws            → aws_access_key_id=", aws_secret_access_key="
python_secret_private_key    → -----BEGIN RSA PRIVATE KEY-----, -----BEGIN PRIVATE KEY-----
python_secret_connection_str → connection string patterns with embedded passwords
```

### BATCH 5 (30 rules) — Framework-Specific JavaScript Depth

**JS SQLi variants (4 new rules):**
```
js_sqli_sequelize            → sequelize.query( with raw SQL, Model.findAll({where: raw})
js_sqli_typeorm              → getRepository().query(, createQueryBuilder().where( with concat
js_sqli_knex                 → knex.raw(, knex.whereRaw(, knex.havingRaw(
js_sqli_mysql2               → pool.query(, connection.query( with string concat
```

Research: `https://sequelize.org/docs/v6/core-concepts/raw-queries/`
Research: `https://typeorm.io/#/select-query-builder`
Research: `https://knexjs.org/guide/raw.html`

**JS NoSQLi variants (3 new rules):**
```
js_nosqli_mongoose           → Model.find({$where:, Model.findOne( with operator injection
js_nosqli_mongodb            → collection.find( with unsanitized object, $regex injection
js_nosqli_firebase           → db.collection(.where( with user input in operator position
```

**JS CMDi variants (3 new rules):**
```
js_cmdi_exec                 → child_process.exec( — always shell, most dangerous
js_cmdi_execsync             → child_process.execSync( — synchronous exec
js_cmdi_spawn_shell          → child_process.spawn( with {shell: true}
```

**JS XSS variants (4 new rules):**
```
js_xss_innerhtml             → element.innerHTML =, element.outerHTML =
js_xss_document_write        → document.write(, document.writeln(
js_xss_eval                  → eval(, new Function(, setTimeout with string arg
js_xss_react_dangerous       → dangerouslySetInnerHTML={{ __html:
```

**JS Path Traversal variants (3 new rules):**
```
js_path_traversal_fs         → fs.readFile(, fs.readFileSync(, fs.createReadStream(
js_path_traversal_express    → res.sendFile(, express.static( with user input
js_path_traversal_require    → require( with user-controlled path
```

**JS Prototype Pollution variants (3 new rules):**
```
js_proto_pollution_merge     → _.merge(, _.defaultsDeep(, $.extend(deep, with user object
js_proto_pollution_assign    → Object.assign( when target is {} and source is user input
js_proto_pollution_json      → JSON.parse( result used as merge source without validation
```

**JS Hardcoded Secret variants (3 new rules):**
```
js_secret_generic            → const apiKey =, const password =, const secret = with string
js_secret_aws                → AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID in string
js_secret_jwt_secret         → jwt.sign(payload, "hardcoded_string") — hardcoded JWT secret
```

**JS Misconfiguration variants (3 new rules):**
```
js_misconfig_debug           → DEBUG=true in production, NODE_ENV !== "production" checks
js_misconfig_helmet          → Express app without helmet() middleware
js_misconfig_cors_wildcard   → cors({origin: "*", credentials: true}) — dangerous combination
```

### BATCH 6 (30 rules) — Framework-Specific Java Depth

**Java SQLi variants (5 new rules):**
```
java_sqli_hibernate          → session.createQuery( with string concat, .createSQLQuery(
java_sqli_spring_jdbc        → jdbcTemplate.execute(, jdbcTemplate.query( with string concat
java_sqli_jpa_native         → entityManager.createNativeQuery( with string concat
java_sqli_mybatis            → @Select with ${} interpolation (not #{} parameterized)
java_sqli_jooq               → DSL.field(, DSL.table( with user-controlled string
```

Research: `https://docs.jboss.org/hibernate/orm/current/userguide/html_single/`
Research: `https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html`
Research: `https://mybatis.org/mybatis-3/sqlmap-xml.html` — ${}  vs #{} distinction

**Java XSS variants (3 new rules):**
```
java_xss_response_writer     → response.getWriter().print(, .write(, .println(
java_xss_spring_model        → model.addAttribute( when rendered without th:text escaping
java_xss_jsp_out             → out.print(, out.write( in JSP scriptlets
```

**Java XXE variants (3 new rules):**
```
java_xxe_documentbuilder     → DocumentBuilderFactory.newInstance( without disabling DTD
java_xxe_saxparser           → SAXParserFactory.newInstance( without disabling entities
java_xxe_stax                → XMLInputFactory.newInstance( without IS_SUPPORTING_EXTERNAL_ENTITIES=false
```

**Java Deserialization variants (5 new rules):**
```
java_deser_xstream           → XStream.fromXML(, new XStream( without security setup
java_deser_jackson_poly      → ObjectMapper with enableDefaultTyping( — polymorphic deserialization
java_deser_snakeyaml         → new Yaml().load( without SafeConstructor
java_deser_kryo              → Kryo.readObject(, Kryo.readClassAndObject(
java_deser_castor            → Unmarshaller.unmarshal( with untrusted input
```

Research: `https://x-stream.github.io/security.html`
Research: `https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062`

**Java CMDi variants (3 new rules):**
```
java_cmdi_runtime            → Runtime.getRuntime().exec( with string concat
java_cmdi_processbuilder     → new ProcessBuilder( with user-controlled command element
java_cmdi_groovy             → GroovyShell.evaluate(, Eval.me( with user input
```

**Java Weak Crypto variants (3 new rules):**
```
java_weak_crypto_md5         → MessageDigest.getInstance("MD5")
java_weak_crypto_sha1        → MessageDigest.getInstance("SHA-1")
java_weak_crypto_ecb         → Cipher.getInstance("AES/ECB", — ECB mode detection
```

**Java SSRF variants (3 new rules):**
```
java_ssrf_urlconnection      → new URL(.openConnection(, URL.openStream(
java_ssrf_httpclient         → HttpClient.newBuilder(, HttpRequest.newBuilder( with user URL
java_ssrf_resttemplate       → RestTemplate.getForEntity(, RestTemplate.postForEntity(
```

### BATCH 7 (30 rules) — Framework-Specific PHP Depth

**PHP SQLi variants (5 new rules):**
```
php_sqli_pdo                 → $pdo->query( with string concat, $pdo->exec(
php_sqli_mysqli              → mysqli_query(, $mysqli->query( with string concat
php_sqli_pgsql               → pg_query(, pg_exec(, pg_send_query( with string concat
php_sqli_mssql               → mssql_query(, sqlsrv_query( with string concat
php_sqli_oci                 → oci_parse(, oci_execute( with unparameterized SQL
```

**PHP CMDi variants (4 new rules):**
```
php_cmdi_system              → system( — outputs result directly
php_cmdi_exec                → exec( — most common CMDi vector
php_cmdi_passthru            → passthru( — outputs raw binary output
php_cmdi_backtick            → backtick operator `` ` `` — shell exec shorthand
```

**PHP Path Traversal variants (4 new rules):**
```
php_path_include             → include(, include_once(, require(, require_once( — LFI
php_path_fopen               → fopen(, file_get_contents(, readfile( with user path
php_path_file_upload         → move_uploaded_file( without proper validation
php_path_zip                 → ZipArchive.extractTo( with path traversal
```

**PHP Deserialization variants (3 new rules):**
```
php_deser_unserialize        → unserialize( — classic PHP object injection
php_deser_phar               → file_exists("phar://", include("phar://", fopen("phar://
php_deser_yaml               → yaml_parse(, Symfony\Component\Yaml\Yaml::parse(
```

**PHP XSS variants (4 new rules):**
```
php_xss_echo                 → echo $user_input — most common PHP XSS pattern
php_xss_print                → print $user_input, printf($format, $user_input)
php_xss_heredoc              → heredoc syntax with unsanitized user vars
php_xss_header               → header("Location: " . $user_input) — header injection
```

**PHP Weak Crypto variants (4 new rules):**
```
php_weak_crypto_md5          → md5( — PHP's built-in MD5 function
php_weak_crypto_sha1         → sha1( — PHP's built-in SHA1 function
php_weak_crypto_des          → mcrypt_encrypt(MCRYPT_DES, — deprecated DES
php_weak_crypto_rand         → rand(, mt_rand( — non-cryptographic PRNG
```

**PHP SSRF variants (3 new rules):**
```
php_ssrf_curl                → curl_setopt($ch, CURLOPT_URL, $user_input)
php_ssrf_file_get            → file_get_contents($url) with user-controlled URL
php_ssrf_http_wrapper        → fopen("http://", include("http://", — HTTP stream wrappers
```

### BATCH 8 (30 rules) — Go + C# Deep Coverage

**Go SQLi variants (3 new rules):**
```
go_sqli_sqlx                 → sqlx.Get(, sqlx.Select(, sqlx.Exec( with raw query string
go_sqli_pgx                  → pgx.Conn.Exec(, pgx.Pool.Query( with string concat
go_sqli_gorm_raw             → gorm.DB.Raw(, gorm.DB.Where( with positional string args
```

Research: `https://pkg.go.dev/github.com/jmoiron/sqlx`
Research: `https://pkg.go.dev/github.com/jackc/pgx/v5`
Research: `https://gorm.io/docs/sql_builder.html`

**Go CMDi variants (2 new rules):**
```
go_cmdi_shell_dash_c         → exec.Command("sh", "-c", userInput) — shell invocation
go_cmdi_bash_dash_c          → exec.Command("bash", "-c", userInput) — bash invocation
```

**Go Path Traversal variants (3 new rules):**
```
go_path_traversal_os         → os.Open(, os.ReadFile(, os.WriteFile( with user path
go_path_traversal_http       → http.ServeFile(, http.Dir( with user-controlled path
go_path_traversal_ioutil     → ioutil.ReadFile(, ioutil.WriteFile( (deprecated but common)
```

**Go SSRF variants (3 new rules):**
```
go_ssrf_default_client       → http.Get(, http.Post(, http.Head( — default client methods
go_ssrf_custom_client        → client.Get(, client.Do(, client.Post( with user URL
go_ssrf_url_parse            → url.Parse( when result used in HTTP request
```

**C# SQLi variants (4 new rules):**
```
csharp_sqli_dapper           → connection.Query(, connection.Execute( with string concat (Dapper)
csharp_sqli_adonet           → new SqlCommand( with string concat
csharp_sqli_oledb            → new OleDbCommand( with string concat
csharp_sqli_npgsql           → new NpgsqlCommand( with string concat
```

Research: `https://dapper-tutorial.net/query`
Research: `https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand`

**C# Path Traversal variants (3 new rules):**
```
csharp_path_file_info        → new FileInfo( with user path
csharp_path_directory        → Directory.GetFiles(, Directory.EnumerateFiles( with user path
csharp_path_stream           → new FileStream(, StreamReader(, StreamWriter( with user path
```

**C# Deserialization variants (3 new rules):**
```
csharp_deser_newtonsoft      → JsonConvert.DeserializeObject( with TypeNameHandling.All
csharp_deser_binaryformatter → BinaryFormatter.Deserialize( — always dangerous, no safe mode
csharp_deser_xmlserializer   → XmlSerializer.Deserialize( with untrusted type
```

**C# XSS variants (2 new rules):**
```
csharp_xss_razor             → @Html.Raw( in Razor views with user data
csharp_xss_response_write    → Response.Write( with user data
```

**C# SSRF variants (2 new rules):**
```
csharp_ssrf_webclient        → new WebClient(.DownloadString(, WebRequest.Create(
csharp_ssrf_httpclient       → HttpClient.GetAsync(, HttpClient.PostAsync( with user URL
```

### BATCH 9 (30 rules) — C/C++ Deep Coverage + Memory Safety

**C Buffer Overflow variants (6 new rules):**
```
c_bof_strcpy                 → strcpy(dest, user_input) — no bounds check
c_bof_strcat                 → strcat(dest, user_input) — no bounds check
c_bof_sprintf                → sprintf(buf, format, user_input) — no size limit
c_bof_gets                   → gets(buf) — always dangerous, no bounds at all
c_bof_memcpy_size            → memcpy(dest, src, user_controlled_size) — size from user
c_bof_scanf                  → scanf("%s", buf) — no width specifier
```

**C Format String variants (3 new rules):**
```
c_fmt_printf                 → printf(user_input) — format string from user
c_fmt_fprintf                → fprintf(fp, user_input) — format string to file
c_fmt_syslog                 → syslog(priority, user_input) — format string to syslog
```

**C Memory Safety variants (3 new rules):**
```
c_null_ptr_deref             → pointer dereference without NULL check (CFG-based, Tentative)
c_race_condition_file        → stat() followed by open() — TOCTOU (CFG-based, Tentative)
c_integer_overflow_malloc    → malloc(user_val * sizeof(type)) — unchecked arithmetic
```

**C++ Buffer Overflow variants (4 new rules):**
```
cpp_bof_cstring              → strcpy(, strcat(, sprintf( — C functions in C++ code
cpp_bof_vector_unchecked     → vector[index] without bounds check vs vector.at(index)
cpp_bof_memcpy               → memcpy(dest, src, user_size) — size from user
cpp_bof_string_copy          → string.copy(buf, n) — manual copy with size
```

**C++ Memory Safety variants (4 new rules):**
```
cpp_uaf_raw_delete           → delete ptr followed by ptr dereference (CFG-based, Tentative)
cpp_null_ptr_deref           → raw pointer dereference without nullptr check (Tentative)
cpp_race_condition_shared    → shared_ptr access without mutex in thread context (Tentative)
cpp_out_of_bounds_array      → array[user_index] without bounds validation
```

**C++ Integer Overflow variants (3 new rules):**
```
cpp_int_overflow_new         → new T[user_size] — array new with unchecked size
cpp_int_overflow_vector      → vector.resize(user_size) — resize with unchecked value
cpp_int_overflow_arithmetic  → user_val1 * user_val2 before malloc/new — unchecked multiply
```

**C++ Format String variants (3 new rules):**
```
cpp_fmt_printf               → printf(user_input) — C-style format string in C++ code
cpp_fmt_sprintf              → sprintf(buf, user_input) — C-style in C++
cpp_fmt_boost_format         → boost::format(user_input) — Boost.Format with user string
```

### BATCH 10 (30 rules) — Security Headers, Config, and Cross-Cutting

**Security Headers (all languages):**
```
python_missing_csp           → Missing Content-Security-Policy header
python_missing_hsts          → Missing Strict-Transport-Security header
python_missing_xframe        → Missing X-Frame-Options header
js_missing_helmet            → Express app without security headers (Helmet)
java_missing_security_filter → Spring Security not configured
php_missing_headers          → Missing security headers in PHP apps
go_missing_security_headers  → Missing security headers in Go HTTP handlers
csharp_missing_headers       → Missing security headers in ASP.NET Core
```

**Session Management:**
```
python_session_fixation      → Session not regenerated after login
python_session_no_expiry     → Session without expiry time
js_session_insecure          → Session secret is weak or hardcoded
java_session_fixation        → session.invalidate() not called before login
php_session_fixation         → session_regenerate_id() not called after login
```

**Cryptography:**
```
python_insecure_random_token → token generated with random.random() not secrets
js_insecure_random           → Math.random() for security token generation
java_insecure_random         → new Random() instead of SecureRandom
php_insecure_random          → rand() or mt_rand() for security tokens
go_insecure_random           → math/rand instead of crypto/rand
csharp_insecure_random       → new Random() instead of RandomNumberGenerator
```

**Dependency/Config:**
```
python_debug_mode            → DEBUG = True in production Flask/Django config
js_node_env_dev              → NODE_ENV !== 'production' in production code
java_spring_debug            → spring.profiles.active=dev in production
php_display_errors           → display_errors = On in php.ini
go_debug_endpoint            → pprof debug endpoint exposed in production
csharp_custom_error_off      → customErrors mode="Off" in web.config
```

---

## REQUIRED SCHEMA FOR ALL NEW RULES

Every rule file must follow this exact schema. No exceptions.

```yaml
# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/{NUMBER}.html
# CodeQL Source:   {URL} or "Not applicable — pattern-based rule"
# Semgrep Source:  {URL} or "Not applicable — pattern-based rule"
# OWASP Cheat:     {URL}
# Verification:    {One sentence naming the source confirming each sink is real}

rule_id: {language}_{vuln_short}_{descriptor}
# Must be globally unique. No two files may share a rule_id.
# Use snake_case. No spaces. No uppercase.

language: python|javascript|java|php|go|csharp|c|cpp

vuln_class: {from allowed list only}

severity: Critical|High|Medium|Low
# Critical = CVSS 9.0-10.0
# High     = CVSS 7.0-8.9
# Medium   = CVSS 4.0-6.9
# Low      = CVSS 0.1-3.9

cwe: CWE-{number}
# Correct CWE verified at mitre.org. Never CWE-1000.

owasp: A{N}:{year}-{Category}
# Correct OWASP Top 10 2021 category.

cvss_score: {float}
# Numerically correct CVSS v3.1 base score.

cvss_vector: CVSS:3.1/{vector}
# Valid CVSS v3.1 vector string.

confidence: Confirmed|Probable|Tentative
# Confirmed  = full taint proof: source → propagation → sink, no sanitizer
# Probable   = strong structural pattern, not full taint proof
# Tentative  = heuristic or CFG-based, requires manual review
#
# MANDATORY Tentative rules (engine cannot confirm these statically):
# - All C/C++ memory rules (buffer overflow, integer overflow, UAF, null ptr, race)
# - All CSRF rules (structural, not taint-based)
# - All Cookie Security rules (absence of flag, not taint-based)
# - All ReDoS rules (pattern on regex string, not taint-based)
# - All Race Condition rules (CFG-based, needs runtime confirmation)
# - All missing security header rules (absence detection)

issue: "{one sentence, names the specific function and the vulnerability}"
# Good: "SQL Injection via Hibernate session.createQuery() with string concatenation"
# Bad:  "SQL Injection detected"
# Bad:  "Security issue (CWE-89)"

message: |-
  {2-4 sentences minimum. Must explain:
  1. Mechanically how the vulnerability works
  2. What an attacker can do with it specifically
  3. Why this specific code pattern creates the risk
  Minimum 80 characters. Must be unique per rule — not copy-pasted.}

sources:
  # Only sources genuinely relevant to THIS specific vuln class.
  # Pattern-based rules (Weak Crypto, Hardcoded Secret, CSRF, Cookie Security,
  # ReDoS, Security Headers, Misconfiguration): sources: []
  # C/C++ rules: sources are stdin, argv, env vars, network recv — not HTTP
  - real_source_function(

sinks:
  # ONLY real functions verified against CodeQL, Semgrep, or official documentation.
  # Every sink must be traceable to a URL in the research evidence comment.
  # Pattern-based rules: sinks: [] (detection uses AST structure not sink matching)
  - real_sink_function(

sanitizers:
  # The SPECIFIC function that neutralizes THIS vulnerability in THIS language.
  # SQLi sanitizer ≠ XSS sanitizer ≠ CMDi sanitizer.
  # If no real sanitizer exists: sanitizers: []
  - real_sanitizer_function(

remediation: |-
  {3-5 sentences. Must include:
  1. What to STOP doing — name the specific vulnerable pattern
  2. What to DO INSTEAD — name the specific safe alternative
  3. A concrete before/after code example in this language
  4. Reference to OWASP Cheat Sheet if applicable
  Minimum 100 characters.}
```

---

## ALLOWED VULN_CLASS VALUES

Use only these exact strings. No variations. No trailing whitespace.

```
SQLi                NoSQLi              CMDi
XSS                 SSTI                SSRF
XXE                 Path Traversal      Open Redirect
Deserialization     Code Injection      LDAP Injection
XPath Injection     Log Injection       Hardcoded Secret
Weak Crypto         JWT Bypass          Prototype Pollution
Buffer Overflow     Integer Overflow    Format String
Use After Free      Memory Corruption   Race Condition
Null Pointer Dereference                ReDoS
CSRF                Misconfiguration    Cookie Security
Mass Assignment     File Upload         Out-of-bounds Read
Cleartext Transmission                  Information Exposure
DoS
```

---

## ABSOLUTE PROHIBITIONS

These will cause the validator to fail. Treat them as hard rules.

**NEVER fabricate sinks.** Every sink must have a research evidence URL.
If you cannot find a real URL for a function, do not write the sink.

**NEVER use these vuln_class values** — they are wrong and will fail validation:
`Type Confusion`, `Log Forging`, `Best Practice`, `Security Issue`, `Injection`,
`Vulnerability`, `Out-of-bounds Read` (use `Memory Corruption` instead unless
the allowed list has been explicitly updated to include it)

**NEVER claim `confidence: Confirmed` for:**
- Any C/C++ memory rule (buffer overflow, integer overflow, UAF, null ptr, race)
- Any CSRF rule
- Any Cookie Security rule
- Any ReDoS rule
- Any Race Condition rule
- Any missing header / misconfiguration rule

**NEVER write useless remediation.** These are rejected:
- `"Validate and sanitize all user input."`
- `"Ensure proper input validation."`
- `"Follow secure coding practices."`

**NEVER copy the same source list to rules that don't need it:**
- Weak Crypto, Hardcoded Secret, ReDoS, CSRF, Cookie Security: `sources: []`
- C/C++ rules: use `stdin, argv, env, recv` — NOT Flask/Django HTTP sources

**NEVER create more than one rule for the same (language + sink function).**
If `cursor.execute(` in Python is already covered, do not create another Python SQLi rule
that also lists `cursor.execute(` as a sink. Use it once per language.

---

## PER-BATCH EXECUTION INSTRUCTIONS

For each batch:

1. **Before writing any YAML:** Complete the research steps for every rule in that batch.
   Record the research evidence URLs before writing any YAML.

2. **Write exactly 30 rules.** Not 29. Not 31. If a rule should not be written
   (e.g., Go Prototype Pollution is not applicable), write a markdown note file
   explaining why and replace it with an additional rule from the next batch.

3. **After writing all 30 rules:** Run the validator below.
   Fix ALL errors before reporting the batch complete.

4. **Report format for each batch:**
   - Batch number and which vuln classes were covered
   - New total rule count
   - For each new rule: rule_id + the 2 research URLs used (CWE + CodeQL/Semgrep)
   - Full validator output showing 0 errors

---

## VALIDATOR — RUN AFTER EVERY BATCH

```python
import yaml, sys
from pathlib import Path

REQUIRED = [
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

FORBIDDEN_CLASSES = {"Type Confusion","Log Forging","Best Practice","Injection"}

MUST_BE_TENTATIVE = {
    "c_use_after_free","c_integer_overflow","c_null_pointer","c_race_condition_file",
    "cpp_use_after_free","cpp_uaf_raw_delete","cpp_null_pointer","cpp_null_ptr_deref",
    "cpp_integer_overflow","cpp_int_overflow_new","cpp_int_overflow_vector",
    "cpp_int_overflow_arithmetic","cpp_out_of_bounds_read","cpp_out_of_bounds_array",
    "cpp_race_condition_shared","c_race_condition",
}

MUST_BE_TENTATIVE_CLASSES = {
    "CSRF","Cookie Security","ReDoS","Race Condition","Misconfiguration",
    "Null Pointer Dereference","Use After Free","Integer Overflow","Buffer Overflow"
}

FORBIDDEN_SINKS = [
    "deprecated_function_","DeprecatedMethod","vulnerableSink",
    "fake_","dummy_","placeholder_","_vuln","vuln_func","test_sink_"
]

USELESS_REMEDIATION = [
    "validate and sanitize all user input",
    "ensure proper input validation",
    "follow secure coding practices"
]

errors, seen_ids = [], {}
per_lang = {}

for f in sorted(Path("rules").rglob("*.yaml")):
    lang = f.parent.name
    per_lang[lang] = per_lang.get(lang, 0) + 1
    try:
        raw = f.read_text(encoding="utf-8")
        rule = yaml.safe_load(raw)
    except Exception as e:
        errors.append(f"PARSE ERROR {f.name}: {e}"); continue
    if not rule:
        errors.append(f"EMPTY: {f.name}"); continue

    for field in REQUIRED:
        if field not in rule:
            errors.append(f"MISSING '{field}': {f.name}")
        elif rule[field] is None or str(rule[field]).strip() == "":
            errors.append(f"EMPTY '{field}': {f.name}")

    rid = str(rule.get("rule_id","")).strip()
    if rid in seen_ids:
        errors.append(f"DUPLICATE rule_id '{rid}': {f.name} + {seen_ids[rid]}")
    else:
        seen_ids[rid] = f.name

    vc = str(rule.get("vuln_class","")).strip()
    if vc in FORBIDDEN_CLASSES:
        errors.append(f"FORBIDDEN vuln_class '{vc}': {f.name}")
    elif vc not in ALLOWED_CLASSES:
        errors.append(f"INVALID vuln_class '{vc}': {f.name}")

    conf = str(rule.get("confidence","")).strip()
    if rid in MUST_BE_TENTATIVE and conf != "Tentative":
        errors.append(f"MUST BE Tentative (got '{conf}'): {f.name}")
    if vc in MUST_BE_TENTATIVE_CLASSES and conf == "Confirmed":
        errors.append(f"CLASS {vc} cannot be Confirmed — use Tentative: {f.name}")

    for sink in (rule.get("sinks",[]) or []):
        for fb in FORBIDDEN_SINKS:
            if fb.lower() in str(sink).lower():
                errors.append(f"FABRICATED SINK '{sink}': {f.name}")

    msg = str(rule.get("message","")).strip()
    if len(msg) < 80:
        errors.append(f"MESSAGE TOO SHORT ({len(msg)} chars): {f.name}")

    rem = str(rule.get("remediation","")).strip()
    for useless in USELESS_REMEDIATION:
        if useless in rem.lower():
            errors.append(f"USELESS REMEDIATION: {f.name}")
    if len(rem) < 100:
        errors.append(f"REMEDIATION TOO SHORT ({len(rem)} chars): {f.name}")

    if "# RESEARCH EVIDENCE" not in raw:
        errors.append(f"MISSING RESEARCH EVIDENCE COMMENT: {f.name}")

total = sum(per_lang.values())
print(f"Total rules: {total}")
print("Per language:", {k: v for k,v in sorted(per_lang.items())})
print(f"Unique IDs: {len(seen_ids)}")
print(f"Errors: {len(errors)}")
for e in errors:
    print(f"  ERROR: {e}")
if not errors:
    print("ALL RULES PASS VALIDATION")
    sys.exit(0)
else:
    sys.exit(1)
```

The validator must output `ALL RULES PASS VALIDATION` after every batch.
A batch is not complete until this passes with zero errors.

---

## REPORTING FORMAT FOR EACH BATCH

Submit exactly this after each batch:

```
BATCH {N} COMPLETE
Rules added: {count}
New total: {count}

New rules written:
  {rule_id} | {vuln_class} | CWE-{N} | {sink function} | {research URL}
  ... (one line per rule)

Rules NOT written (not applicable):
  {filename_NOT_APPLICABLE.md} — {one sentence reason}

Validator output:
  Total rules: {N}
  Errors: 0
  ALL RULES PASS VALIDATION
```

Do not submit a batch report without the validator output.
Do not proceed to the next batch until the current batch passes validation.
Do not add rules not on the batch list without asking first.
```
