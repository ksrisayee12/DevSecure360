from rule_writer import write_rule

JS_SOURCES = [
    "req.body", "req.query", "req.params", "req.headers", "req.cookies",
    "window.location", "document.cookie", "process.argv", "process.env"
]

def gen_js_rules():
    # Batch 5: SQLi Variants
    write_rule(
        "javascript", "js_sqli_sequelize", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in Sequelize",
        "User input is directly concatenated into a raw SQL query executed via Sequelize. An attacker can manipulate the query to extract sensitive data or modify the database.",
        JS_SOURCES,
        ["sequelize.query(", "Model.findAll({where:"],
        [],
        "Always use Sequelize's built-in parameterized replacements (e.g., replacements: { param: value }) or bind parameters instead of string concatenation."
    )

    write_rule(
        "javascript", "js_sqli_typeorm", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in TypeORM",
        "User input is directly concatenated into a TypeORM queryBuilder or raw query. This can lead to SQL injection attacks that compromise the database.",
        JS_SOURCES,
        ["getRepository().query(", "createQueryBuilder().where("],
        [],
        "Use parameterized queries with TypeORM queryBuilder using setParameters or pass parameters as the second argument to raw query functions."
    )

    write_rule(
        "javascript", "js_sqli_knex", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in Knex.js",
        "Raw SQL is executed using Knex.js raw methods with unparameterized user input, allowing attackers to inject malicious SQL logic.",
        JS_SOURCES,
        ["knex.raw(", "knex.whereRaw(", "knex.havingRaw("],
        [],
        "Use Knex's built-in bindings for raw queries, such as knex.raw('... ?', [value]), to ensure parameters are properly escaped."
    )

    write_rule(
        "javascript", "js_sqli_mysql2", "SQLi", "High", "CWE-89", "A03:2021-Injection", 8.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection in MySQL2",
        "Queries are constructed using string concatenation with the mysql or mysql2 drivers. This directly introduces SQL injection vulnerabilities.",
        JS_SOURCES,
        ["pool.query(", "connection.query("],
        [],
        "Use parameterized queries with placeholders (?) and pass values in an array as the second argument to the query function."
    )

    # Batch 5: NoSQLi Variants
    write_rule(
        "javascript", "js_nosqli_mongoose", "NoSQLi", "High", "CWE-943", "A03:2021-Injection", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Confirmed",
        "NoSQL Injection in Mongoose",
        "Untrusted user input is passed directly into Mongoose query filters, especially using $where operators, which can execute arbitrary JavaScript.",
        JS_SOURCES,
        ["Model.find({$where:", "Model.findOne("],
        [],
        "Avoid using $where queries where possible. Strongly type cast and sanitize all user input before passing it into Mongoose query objects."
    )

    write_rule(
        "javascript", "js_nosqli_mongodb", "NoSQLi", "High", "CWE-943", "A03:2021-Injection", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Confirmed",
        "NoSQL Injection in MongoDB Native Driver",
        "User input is directly injected into MongoDB native driver queries, potentially allowing attackers to modify query logic or extract data via operators like $ne or $regex.",
        JS_SOURCES,
        ["collection.find("],
        [],
        "Sanitize all user input keys to prevent operator injection (e.g., removing keys starting with $) and enforce strict schema validation."
    )

    write_rule(
        "javascript", "js_nosqli_firebase", "NoSQLi", "Medium", "CWE-943", "A03:2021-Injection", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "Tentative",
        "NoSQL Injection in Firebase/Firestore",
        "User input is used as the operator or value in Firebase/Firestore queries without validation, potentially allowing unauthorized data access.",
        JS_SOURCES,
        ["db.collection(.where("],
        [],
        "Do not use user input for query operators. Strictly validate and sanitize values used in Firebase query parameters."
    )

    # Batch 5: CMDi Variants
    write_rule(
        "javascript", "js_cmdi_exec", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via child_process.exec",
        "Untrusted user input is passed to child_process.exec(), which executes commands in a shell environment, allowing arbitrary OS command execution.",
        JS_SOURCES,
        ["child_process.exec("],
        [],
        "Avoid executing OS commands if possible. If required, use child_process.execFile() with an array of arguments to prevent shell evaluation."
    )

    write_rule(
        "javascript", "js_cmdi_execsync", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via child_process.execSync",
        "Untrusted user input is passed to child_process.execSync(), causing synchronous execution of arbitrary commands within a shell.",
        JS_SOURCES,
        ["child_process.execSync("],
        [],
        "Do not use execSync with untrusted input. Prefer execFileSync and explicitly define the executable path and arguments array."
    )

    write_rule(
        "javascript", "js_cmdi_spawn_shell", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via spawn with shell: true",
        "Using child_process.spawn() with the {shell: true} option passes arguments to a system shell, exposing the application to command injection if input is untrusted.",
        JS_SOURCES,
        ["child_process.spawn("],
        [],
        "Never use the {shell: true} option with spawn when processing untrusted input. Pass arguments directly as an array instead."
    )

    # Batch 5: XSS Variants
    write_rule(
        "javascript", "js_xss_innerhtml", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "DOM-based XSS via innerHTML",
        "Untrusted data is assigned directly to the innerHTML or outerHTML properties of a DOM element, allowing execution of malicious JavaScript.",
        JS_SOURCES,
        ["element.innerHTML =", "element.outerHTML ="],
        [],
        "Use element.textContent or element.innerText instead of innerHTML to safely render untrusted data as text rather than HTML."
    )

    write_rule(
        "javascript", "js_xss_document_write", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "DOM-based XSS via document.write",
        "Untrusted data is written directly to the document using document.write() or document.writeln(), causing immediate execution of injected scripts.",
        JS_SOURCES,
        ["document.write(", "document.writeln("],
        [],
        "Avoid using document.write() entirely. Use modern DOM manipulation methods like document.createElement() and textContent."
    )

    write_rule(
        "javascript", "js_xss_eval", "XSS", "Critical", "CWE-79", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Code Injection via eval() or Similar Methods",
        "Untrusted input is passed to eval(), new Function(), or setTimeout/setInterval with a string argument, leading to arbitrary JavaScript execution.",
        JS_SOURCES,
        ["eval(", "new Function(", "setTimeout(", "setInterval("],
        [],
        "Never pass string arguments containing user input to eval(), new Function(), or timing functions. Pass functions as callbacks instead."
    )

    write_rule(
        "javascript", "js_xss_react_dangerous", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "XSS via dangerouslySetInnerHTML in React",
        "Untrusted data is passed to React's dangerouslySetInnerHTML prop, bypassing React's built-in XSS protection and rendering raw HTML.",
        JS_SOURCES,
        ["dangerouslySetInnerHTML={{ __html:"],
        [],
        "Avoid dangerouslySetInnerHTML. If HTML must be rendered, aggressively sanitize the input using a library like DOMPurify before rendering."
    )

    # Batch 5: Path Traversal Variants
    write_rule(
        "javascript", "js_path_traversal_fs", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via File System API",
        "User input is passed to Node.js fs methods (e.g., readFile, createReadStream) without sanitization, allowing attackers to access unauthorized files on the server.",
        JS_SOURCES,
        ["fs.readFile(", "fs.readFileSync(", "fs.createReadStream("],
        [],
        "Validate and normalize file paths using path.resolve() and ensure the resulting path strictly resides within the intended base directory."
    )

    write_rule(
        "javascript", "js_path_traversal_express", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via Express Response",
        "Untrusted input is used in res.sendFile() or express.static() without setting the 'root' option securely, potentially leaking arbitrary files.",
        JS_SOURCES,
        ["res.sendFile(", "express.static("],
        [],
        "Always define a secure 'root' property in the options object of res.sendFile() to restrict file access to the specific directory."
    )

    write_rule(
        "javascript", "js_path_traversal_require", "Path Traversal", "Critical", "CWE-22", "A01:2021-Broken Access Control", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Path Traversal / LFI via require()",
        "User input controls the module path passed to require(), allowing Local File Inclusion (LFI) and potential arbitrary code execution.",
        JS_SOURCES,
        ["require("],
        [],
        "Never use unvalidated user input in require() calls. Use a strict allowlist mapping input strings to safe, hardcoded module paths."
    )

    # Batch 5: Prototype Pollution Variants
    write_rule(
        "javascript", "js_proto_pollution_merge", "Prototype Pollution", "High", "CWE-1321", "A08:2021-Software and Data Integrity Failures", 7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "Confirmed",
        "Prototype Pollution via Deep Merge",
        "Untrusted input is recursively merged into objects using libraries like lodash (_.merge) or jQuery ($.extend(true)), modifying the global Object.prototype.",
        JS_SOURCES,
        ["_.merge(", "_.defaultsDeep(", "$.extend(true,"],
        [],
        "Update library versions to patched releases. Alternatively, use Safe Map objects or freeze Object.prototype using Object.freeze(Object.prototype)."
    )

    write_rule(
        "javascript", "js_proto_pollution_assign", "Prototype Pollution", "Medium", "CWE-1321", "A08:2021-Software and Data Integrity Failures", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Tentative",
        "Prototype Pollution via Object.assign",
        "Untrusted objects are passed to Object.assign(), which may allow property injection if the source objects contain malicious __proto__ properties.",
        JS_SOURCES,
        ["Object.assign("],
        [],
        "Ensure untrusted inputs are securely sanitized before assignment. Create objects with null prototypes using Object.create(null) for safe data storage."
    )

    write_rule(
        "javascript", "js_proto_pollution_json", "Prototype Pollution", "High", "CWE-1321", "A08:2021-Software and Data Integrity Failures", 7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "Tentative",
        "Prototype Pollution via JSON Parsing",
        "Parsed JSON data containing malicious __proto__ properties is directly used in assignments or merges, corrupting prototype chains.",
        JS_SOURCES,
        ["JSON.parse("],
        [],
        "Implement a custom reviver function in JSON.parse() to explicitly reject __proto__ and constructor properties during parsing."
    )

    # Batch 5: Hardcoded Secret Variants
    write_rule(
        "javascript", "js_secret_generic", "Hardcoded Secret", "High", "CWE-798", "A07:2021-Identification and Authentication Failures", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Hardcoded Generic Secret Token",
        "Sensitive information such as API keys, passwords, or tokens are hardcoded as string literals in the source code.",
        [],
        ["const apiKey =", "const password =", "const secret =", "let api_key =", "let token ="],
        [],
        "Remove hardcoded secrets from source code. Load sensitive values from environment variables or a secure secret management service."
    )

    write_rule(
        "javascript", "js_secret_aws", "Hardcoded Secret", "Critical", "CWE-798", "A07:2021-Identification and Authentication Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Hardcoded AWS Credentials",
        "AWS access keys (e.g., AKIA...) or secret keys are hardcoded in the codebase, leading to full compromise of associated cloud resources.",
        [],
        ["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"],
        [],
        "Never hardcode AWS credentials. Utilize AWS IAM roles, instance profiles, or securely configured environment variables for authentication."
    )

    write_rule(
        "javascript", "js_secret_jwt_secret", "Hardcoded Secret", "High", "CWE-798", "A07:2021-Identification and Authentication Failures", 8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Hardcoded JWT Signing Secret",
        "The application signs JSON Web Tokens (JWTs) using a hardcoded secret string. Attackers can forge valid JWTs to impersonate any user.",
        [],
        ["jwt.sign(payload,", "jwt.verify(token,"],
        [],
        "Do not use hardcoded strings for JWT secrets. Generate a strong random key and load it securely from environment configurations at runtime."
    )

    # Batch 5: Misconfiguration Variants
    write_rule(
        "javascript", "js_misconfig_debug", "Misconfiguration", "Medium", "CWE-16", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Confirmed",
        "Debug Mode Enabled in Production",
        "The application is configured to run in debug mode or bypasses production checks, potentially exposing stack traces and sensitive internal variables.",
        [],
        ["DEBUG=true", "NODE_ENV !== 'production'"],
        [],
        "Ensure debug modes are strictly disabled in production environments. Use NODE_ENV='production' to enforce secure defaults in frameworks."
    )

    write_rule(
        "javascript", "js_misconfig_helmet", "Misconfiguration", "Medium", "CWE-16", "A05:2021-Security Misconfiguration", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "Tentative",
        "Missing Helmet Security Middleware",
        "The Express application does not appear to use the Helmet middleware, leaving it vulnerable to various attacks due to missing secure HTTP headers.",
        [],
        ["express()", "app.listen("],
        [],
        "Integrate the 'helmet' middleware (app.use(helmet())) to automatically set crucial security headers like Content-Security-Policy and X-Frame-Options."
    )

    write_rule(
        "javascript", "js_misconfig_cors_wildcard", "Misconfiguration", "High", "CWE-942", "A05:2021-Security Misconfiguration", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Dangerous CORS Wildcard Configuration",
        "The CORS configuration combines origin: '*' with credentials: true. This allows any malicious website to read authenticated cross-origin responses.",
        [],
        ["cors({origin: \"*\"", "cors({origin: '*'"],
        [],
        "Do not use wildcard origins with credentials. Explicitly specify the exact trusted origins in the CORS configuration allowlist."
    )

if __name__ == '__main__':
    gen_js_rules()
