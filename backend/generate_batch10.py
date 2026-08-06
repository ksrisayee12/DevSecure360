import os
import yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app', 'scanner', 'sast', 'rules')

RESEARCH_HEADER = '''# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/693.html
# CodeQL Source:   Not applicable — absence-based structural detection
# Semgrep Source:  https://semgrep.dev/r?q=security+headers+misconfiguration
# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Reference_Cheat_Sheet.html
# Verification:    Security header absence detection is structural/pattern-based. Rule is Tentative.'''

RESEARCH_SESSION = '''# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/16.html
# CodeQL Source:   Not applicable — structural configuration detection
# Semgrep Source:  https://semgrep.dev/r?q=session+misconfiguration
# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
# Verification:    Insecure session configuration patterns verified from OWASP Session Management Cheat Sheet.'''

RESEARCH_DEBUG = '''# RESEARCH EVIDENCE
# CWE Source:      https://cwe.mitre.org/data/definitions/489.html
# CodeQL Source:   Not applicable — structural configuration detection
# Semgrep Source:  https://semgrep.dev/r?q=debug+mode+production
# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
# Verification:    Debug mode enabled in production is a well-documented misconfiguration per OWASP.'''

class LiteralStr(str): pass

def literal_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(LiteralStr, literal_presenter)

def write_rule(lang, rule_id, research_comment, issue, message, remediation,
               severity='Medium', cwe='CWE-693', owasp='A05:2021-Security Misconfiguration',
               cvss_score=5.3, cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'):
    lang_dir = os.path.join(RULES_DIR, lang)
    os.makedirs(lang_dir, exist_ok=True)
    filepath = os.path.join(lang_dir, rule_id + '.yaml')
    rule = {
        'rule_id': rule_id, 'language': lang, 'vuln_class': 'Misconfiguration',
        'severity': severity, 'cwe': cwe, 'owasp': owasp,
        'cvss_score': cvss_score, 'cvss_vector': cvss_vector,
        'confidence': 'Tentative', 'issue': issue,
        'message': LiteralStr(message.strip()),
        'sources': [], 'sinks': [], 'sanitizers': [],
        'remediation': LiteralStr(remediation.strip()),
    }
    content = research_comment.strip() + '\n\n' + yaml.dump(rule, default_flow_style=False, allow_unicode=True, sort_keys=False)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Written: ' + rule_id)

# PYTHON (6 rules)
write_rule('python', 'python_missing_hsts', RESEARCH_HEADER,
    issue='Missing HTTP Strict-Transport-Security (HSTS) header in Flask/Django response',
    message='The application does not set the Strict-Transport-Security response header, allowing browsers to access it over plain HTTP even when HTTPS is available. An attacker performing a man-in-the-middle attack can downgrade the connection to HTTP and intercept sensitive data including session cookies and credentials.',
    remediation='Add the Strict-Transport-Security header to all HTTPS responses with a max-age of at least 31536000 seconds and the includeSubDomains directive.\n\nUNSAFE (Flask): No HSTS header set in after_request handler.\nSAFE:\n  @app.after_request\n  def add_hsts(response):\n      response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n      return response\n\nSee OWASP HTTP Headers Reference Cheat Sheet for complete configuration guidance.'
)

write_rule('python', 'python_missing_csp', RESEARCH_HEADER,
    issue='Missing Content-Security-Policy (CSP) header in Flask/Django response',
    message='The application does not set a Content-Security-Policy response header, leaving users vulnerable to XSS attacks that could execute malicious scripts without browser-level mitigation. Without CSP, a successful XSS injection can steal session tokens, exfiltrate data, or perform actions as the victim.',
    remediation='Add a strict Content-Security-Policy header to all responses using an after_request hook or middleware.\n\nUNSAFE (Flask): No Content-Security-Policy header configured.\nSAFE:\n  @app.after_request\n  def add_csp(response):\n      response.headers["Content-Security-Policy"] = "default-src ' + "'self'" + '"\n      return response\n\nUse the Flask-Talisman extension to manage all security headers declaratively.'
)

write_rule('python', 'python_missing_xframe_options', RESEARCH_HEADER,
    issue='Missing X-Frame-Options header in Flask/Django response allows clickjacking attacks',
    message='The application does not set the X-Frame-Options response header, allowing the application page to be embedded in an iframe on any external website. An attacker can perform a clickjacking attack by overlaying an invisible frame to trick authenticated users into clicking hidden UI elements and performing unintended privileged actions.',
    remediation='Add X-Frame-Options: DENY to all responses to prevent iframe embedding.\n\nUNSAFE (Flask): No X-Frame-Options header in response.\nSAFE:\n  @app.after_request\n  def add_xframe(response):\n      response.headers["X-Frame-Options"] = "DENY"\n      return response\n\nAlternatively use the CSP frame-ancestors directive for modern browsers with finer-grained control.'
)

write_rule('python', 'python_missing_xcontent_type', RESEARCH_HEADER,
    issue='Missing X-Content-Type-Options header in Flask/Django response enables MIME sniffing',
    message='The application does not set the X-Content-Type-Options: nosniff header, allowing browsers to MIME-sniff response content types. An attacker who controls uploaded file content could cause the browser to interpret a resource served as text/plain as executable JavaScript, enabling script injection despite a safe declared MIME type.',
    remediation='Set X-Content-Type-Options: nosniff on all responses to disable browser MIME sniffing.\n\nUNSAFE (Flask): No X-Content-Type-Options header.\nSAFE:\n  @app.after_request\n  def add_xcto(response):\n      response.headers["X-Content-Type-Options"] = "nosniff"\n      return response\n\nConsider Flask-Talisman for declarative management of all security response headers.'
)

write_rule('python', 'python_flask_debug_enabled', RESEARCH_DEBUG,
    issue='Flask application running with DEBUG=True exposing the interactive Werkzeug debugger',
    cwe='CWE-489', severity='High', cvss_score=8.1,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    message='The Flask application is started with debug=True or DEBUG=True in config. This activates the Werkzeug interactive debugger which exposes a Python console in the browser on any unhandled exception. An attacker who triggers an error can execute arbitrary Python code on the server with full application privileges, constituting critical remote code execution.',
    remediation='Disable debug mode for all production deployments. Control this via an environment variable, never hardcode it.\n\nUNSAFE:\n  app.run(debug=True)\n  app.config["DEBUG"] = True\n\nSAFE:\n  app.run(debug=os.environ.get("FLASK_DEBUG", "False") == "True")\n\nIn production, use a proper WSGI server (Gunicorn, uWSGI) rather than the built-in development server. Never commit debug=True to version control.'
)

write_rule('python', 'python_weak_session_secret', RESEARCH_SESSION,
    issue='Flask application using a weak or hardcoded SECRET_KEY for session cookie signing',
    cwe='CWE-16', severity='High', cvss_score=7.5,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    message='The Flask application uses a hardcoded or weak SECRET_KEY (such as "dev", "secret", or an empty string) for signing session cookies. An attacker who can guess or brute-force this key can forge valid session cookies for any user account including administrators, achieving complete authentication bypass without requiring credentials.',
    remediation='Use a cryptographically random SECRET_KEY loaded from an environment variable or secrets manager at runtime.\n\nUNSAFE:\n  app.config["SECRET_KEY"] = "dev"\n  app.config["SECRET_KEY"] = "secret123"\n\nSAFE:\n  import os\n  app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]\n  # Generate with: python -c "import secrets; print(secrets.token_hex(32))"\n\nRotate the key immediately if it was ever exposed. Use a secrets manager in production.'
)

# JAVASCRIPT (5 rules)
write_rule('javascript', 'js_missing_hsts', RESEARCH_HEADER,
    issue='Missing Strict-Transport-Security (HSTS) header in Express.js HTTP responses',
    message='The Express.js application does not set the Strict-Transport-Security response header. Without HSTS, browsers that initially connect over HTTP are not instructed to use HTTPS, leaving them vulnerable to SSL-stripping man-in-the-middle attacks. Intercepted connections expose session tokens, credentials, and sensitive user data.',
    remediation='Enable HSTS using the Helmet middleware which sets this and other security headers by default.\n\nUNSAFE: No HSTS header set; plain HTTP connections are not rejected.\nSAFE:\n  const helmet = require("helmet");\n  app.use(helmet({\n    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }\n  }));\n\nEnsure your server also redirects all HTTP traffic to HTTPS before relying on HSTS enforcement.'
)

write_rule('javascript', 'js_missing_csp', RESEARCH_HEADER,
    issue='Missing Content-Security-Policy header in Express.js responses',
    message='The Express.js application does not configure a Content-Security-Policy header. Without CSP, any XSS vulnerability has no browser-level defense to restrict script execution or resource loading. A successful XSS attack can steal session cookies, exfiltrate form data, or perform authenticated requests to the server on behalf of the victim user.',
    remediation='Configure a Content-Security-Policy using Helmet\'s contentSecurityPolicy middleware.\n\nUNSAFE: No Content-Security-Policy header configured in the Express pipeline.\nSAFE:\n  const helmet = require("helmet");\n  app.use(helmet.contentSecurityPolicy({\n    directives: {\n      defaultSrc: ["\'self\'"],\n      scriptSrc: ["\'self\'"]\n    }\n  }));\n\nTest your policy with Google CSP Evaluator before deploying. Avoid using \'unsafe-inline\' or \'unsafe-eval\'.'
)

write_rule('javascript', 'js_missing_xframe_options', RESEARCH_HEADER,
    issue='Missing X-Frame-Options header in Express.js response allows clickjacking',
    message='The Express.js application does not set the X-Frame-Options response header, allowing the application to be embedded in iframes by any third-party website. Attackers can perform clickjacking by overlaying a transparent iframe on top of legitimate UI elements, causing authenticated users to unknowingly click hidden buttons that perform state-changing privileged operations.',
    remediation='Set X-Frame-Options using Helmet\'s frameguard middleware.\n\nUNSAFE: No X-Frame-Options header in Express response pipeline.\nSAFE:\n  const helmet = require("helmet");\n  app.use(helmet.frameguard({ action: "deny" }));\n\nAlternatively configure the Content-Security-Policy frame-ancestors directive, which is more expressive and supported by modern browsers.'
)

write_rule('javascript', 'js_missing_xcontent_type', RESEARCH_HEADER,
    issue='Missing X-Content-Type-Options header in Express.js response enables MIME sniffing',
    message='The Express.js application does not send the X-Content-Type-Options: nosniff header. Without this, browsers may MIME-sniff response content and execute it as a different type than declared. This is a significant risk when the application serves user-uploaded files, as a malicious file served as text/plain could be executed as JavaScript by the browser.',
    remediation='Enable the noSniff header via Helmet\'s noSniff middleware.\n\nUNSAFE: No X-Content-Type-Options header in responses.\nSAFE:\n  const helmet = require("helmet");\n  app.use(helmet.noSniff());\n  // Or helmet() applies noSniff automatically by default.\n\nThis header must be applied globally to all routes, especially those serving user-controlled content.'
)

write_rule('javascript', 'js_session_insecure_config', RESEARCH_SESSION,
    issue='Express-session cookie missing Secure, HttpOnly, and SameSite security attributes',
    cwe='CWE-16',
    message='The Express.js session is configured without the Secure, HttpOnly, and SameSite cookie flags. A session cookie without Secure can be transmitted over unencrypted HTTP. Without HttpOnly the cookie is accessible to JavaScript, enabling theft via XSS. Without SameSite the session is vulnerable to cross-site request forgery on older CSRF-protected endpoints.',
    remediation='Configure express-session with full cookie security options.\n\nUNSAFE:\n  app.use(session({ secret: "key", resave: false }));\n\nSAFE:\n  app.use(session({\n    secret: process.env.SESSION_SECRET,\n    resave: false,\n    saveUninitialized: false,\n    cookie: { secure: true, httpOnly: true, sameSite: "strict" }\n  }));\n\nSee OWASP Session Management Cheat Sheet for complete Node.js session hardening guidance.'
)

# JAVA (5 rules)
write_rule('java', 'java_missing_hsts', RESEARCH_HEADER,
    issue='Missing Strict-Transport-Security (HSTS) header in Spring Security configuration',
    message='The Spring application does not configure Strict-Transport-Security via Spring Security HTTP headers. Without HSTS, browsers are not forced to use HTTPS for subsequent requests, leaving users vulnerable to SSL-stripping and man-in-the-middle attacks. Intercepted connections expose session tokens, credentials, and sensitive application data.',
    remediation='Enable HSTS in Spring Security HttpSecurity configuration.\n\nUNSAFE: No HSTS configured — Spring Security default may omit this header.\nSAFE:\n  http.headers(headers -> headers\n      .httpStrictTransportSecurity(hsts -> hsts\n          .includeSubDomains(true)\n          .maxAgeInSeconds(31536000)\n          .preload(true)\n      )\n  );\n\nHSTS only works over HTTPS; also call http.requiresChannel().anyRequest().requiresSecure().'
)

write_rule('java', 'java_missing_csp', RESEARCH_HEADER,
    issue='Missing Content-Security-Policy header in Spring Security configuration',
    message='The Spring application does not configure a Content-Security-Policy response header via Spring Security. Without CSP, any XSS vulnerability has no browser-level enforcement layer to restrict script execution or data exfiltration. A successful XSS attack can steal authenticated session tokens and perform actions on behalf of the victim.',
    remediation='Configure a Content-Security-Policy header in Spring Security.\n\nUNSAFE: No CSP configured in Spring Security headers block.\nSAFE:\n  http.headers(headers -> headers\n      .contentSecurityPolicy(csp -> csp\n          .policyDirectives("default-src \'self\'; script-src \'self\'")\n      )\n  );\n\nTest the policy with Google CSP Evaluator. Avoid unsafe-inline and unsafe-eval directives.'
)

write_rule('java', 'java_missing_xframe_options', RESEARCH_HEADER,
    issue='Missing X-Frame-Options header in Spring Security configuration allows clickjacking',
    message='The Spring application does not explicitly configure X-Frame-Options in Spring Security, or has disabled frame options. Without this protection, the application can be embedded in an iframe on any external domain. Attackers use this to perform clickjacking attacks, tricking authenticated users into performing unintended privileged operations through invisible overlay iframes.',
    remediation='Set frame options to DENY in Spring Security configuration.\n\nUNSAFE: frameOptions disabled or not explicitly configured.\nSAFE:\n  http.headers(headers -> headers\n      .frameOptions(frame -> frame.deny())\n  );\n\nSpring Security enables SAMEORIGIN by default in older versions; explicitly set DENY unless your application requires framing from the same origin.'
)

write_rule('java', 'java_missing_xcontent_type', RESEARCH_HEADER,
    issue='Missing X-Content-Type-Options header in Spring Security configuration',
    message='The Spring application does not set the X-Content-Type-Options: nosniff response header via Spring Security. Without this header browsers can MIME-sniff content types, potentially treating user-uploaded files as executable scripts. This significantly amplifies the impact of any file upload vulnerability present in the application.',
    remediation='Enable content type options in Spring Security headers.\n\nUNSAFE: contentTypeOptions disabled or not configured.\nSAFE:\n  http.headers(headers -> headers\n      .contentTypeOptions(Customizer.withDefaults())\n  );\n  // Spring Security enables nosniff by default — verify it has not been explicitly disabled.\n\nVerify using browser developer tools that X-Content-Type-Options: nosniff appears in all responses.'
)

write_rule('java', 'java_session_fixation', RESEARCH_SESSION,
    issue='HttpSession not invalidated and regenerated after authentication, enabling session fixation',
    cwe='CWE-384',
    message='The Java Servlet application does not invalidate the pre-authentication HttpSession and create a new session after a successful login event. An attacker who can obtain a valid pre-login session ID can wait for the victim to authenticate, then use the same session ID to gain authenticated access without ever providing credentials.',
    remediation='Invalidate the old session and create a new one immediately after a successful login.\n\nUNSAFE:\n  // User authenticates but session ID is not regenerated\n  session.setAttribute("user", username);\n\nSAFE:\n  HttpSession old = request.getSession(false);\n  if (old != null) { old.invalidate(); }\n  HttpSession newSession = request.getSession(true);\n  newSession.setAttribute("user", username);\n\nSpring Security handles session fixation protection automatically via SessionFixationProtectionStrategy. Ensure it is not disabled in your configuration.'
)

# PHP (5 rules)
write_rule('php', 'php_missing_hsts', RESEARCH_HEADER,
    issue='Missing Strict-Transport-Security (HSTS) header in PHP HTTP response',
    message='The PHP application does not send the Strict-Transport-Security response header. Without HSTS, browsers do not enforce HTTPS for subsequent requests, leaving users exposed to SSL-stripping man-in-the-middle attacks. An attacker positioned between the user and the server can intercept HTTP connections to steal session cookies and credentials.',
    remediation='Set the HSTS header on all PHP HTTPS responses in a central location.\n\nUNSAFE: No Strict-Transport-Security header sent in responses.\nSAFE:\n  header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");\n\nAdd this to a bootstrap file or front controller that runs on every request. Configure in web server (nginx/Apache) headers for best coverage.'
)

write_rule('php', 'php_missing_csp', RESEARCH_HEADER,
    issue='Missing Content-Security-Policy header in PHP HTTP response',
    message='The PHP application does not emit a Content-Security-Policy response header. Without CSP, any reflected or stored XSS vulnerability has no browser-level defense. A successful XSS attack can steal authenticated session cookies via document.cookie, exfiltrate form inputs, or make authenticated requests to the server on behalf of the victim user.',
    remediation='Set a Content-Security-Policy header in all PHP responses from a central location.\n\nUNSAFE: No Content-Security-Policy header emitted.\nSAFE:\n  header("Content-Security-Policy: default-src \'self\'; script-src \'self\'");\n\nApply in a global bootstrap file before any output. Test your policy with a CSP evaluator tool before deployment.'
)

write_rule('php', 'php_missing_xframe_options', RESEARCH_HEADER,
    issue='Missing X-Frame-Options header in PHP response allows clickjacking',
    message='The PHP application does not set the X-Frame-Options response header, permitting the application to be embedded in an iframe by any external website. Clickjacking attacks can exploit this by overlaying an invisible frame on top of a trusted-looking page to trick authenticated users into clicking hidden buttons that perform unintended privileged operations.',
    remediation='Send the X-Frame-Options header in all PHP responses.\n\nUNSAFE: No X-Frame-Options header.\nSAFE:\n  header("X-Frame-Options: DENY");\n  // Or for same-origin framing:\n  header("X-Frame-Options: SAMEORIGIN");\n\nAdd to a front controller or bootstrap file applied to every request. The Content-Security-Policy frame-ancestors directive is the modern equivalent with more control.'
)

write_rule('php', 'php_session_ini_insecure', RESEARCH_SESSION,
    issue='PHP session cookie missing HttpOnly or Secure flags in session configuration',
    cwe='CWE-16',
    message='The PHP application configures sessions without enabling the cookie_httponly or cookie_secure flags. A session cookie without HttpOnly is accessible to client-side JavaScript, enabling theft via any XSS vulnerability. A cookie without the Secure flag may be sent over unencrypted HTTP connections and intercepted by network attackers.',
    remediation='Configure PHP session cookies with HttpOnly, Secure, and SameSite attributes before calling session_start().\n\nUNSAFE:\n  ini_set("session.cookie_httponly", 0);\n  session_start();\n\nSAFE:\n  ini_set("session.cookie_httponly", 1);\n  ini_set("session.cookie_secure", 1);\n  ini_set("session.cookie_samesite", "Strict");\n  session_start();\n\nSee OWASP Session Management Cheat Sheet for comprehensive PHP session security guidance.'
)

write_rule('php', 'php_expose_php', RESEARCH_DEBUG,
    issue='PHP expose_php = On reveals server PHP version in X-Powered-By response header',
    cwe='CWE-489',
    message='The PHP application has expose_php enabled (the default), causing all HTTP responses to include an X-Powered-By: PHP/x.y.z header that reveals the exact PHP version. Attackers use this to identify the server\'s PHP version and target known CVEs specific to that release, significantly reducing reconnaissance effort required before exploitation.',
    remediation='Disable expose_php in php.ini to suppress PHP version disclosure in HTTP headers.\n\nUNSAFE (php.ini):\n  expose_php = On\n\nSAFE:\n  ; In php.ini:\n  expose_php = Off\n\n  ; Or remove programmatically (before output):\n  header_remove("X-Powered-By");\n\nAlso remove server version banners from your web server configuration (ServerTokens Prod for Apache, server_tokens off for nginx).'
)

# GO (5 rules)
write_rule('go', 'go_missing_hsts', RESEARCH_HEADER,
    issue='Missing Strict-Transport-Security (HSTS) header in Go net/http handler',
    message='The Go HTTP handler does not set the Strict-Transport-Security response header. Without HSTS, browsers that initially connect over HTTP will continue to do so even if HTTPS is available, leaving them open to SSL-stripping man-in-the-middle attacks. Intercepted connections expose session tokens, credentials, and private application data.',
    remediation='Set the HSTS header in a Go HTTP middleware applied globally.\n\nUNSAFE: No HSTS header set in HTTP handlers.\nSAFE:\n  func secureHeaders(next http.Handler) http.Handler {\n      return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n          w.Header().Set("Strict-Transport-Security",\n              "max-age=31536000; includeSubDomains")\n          next.ServeHTTP(w, r)\n      })\n  }\n\nConsider using the unrolled/secure package which provides a comprehensive Go security headers middleware.'
)

write_rule('go', 'go_missing_csp', RESEARCH_HEADER,
    issue='Missing Content-Security-Policy header in Go net/http handler',
    message='The Go HTTP application does not set a Content-Security-Policy response header. Without CSP, any XSS vulnerability present in the application has no browser-level restriction on what scripts can execute or what resources can be loaded. A successful XSS attack allows the attacker to steal session tokens, perform authenticated API calls, and exfiltrate sensitive data.',
    remediation='Set the Content-Security-Policy header in a global Go HTTP middleware.\n\nUNSAFE: No Content-Security-Policy header in handler or middleware.\nSAFE:\n  w.Header().Set("Content-Security-Policy", "default-src \'self\'")\n\nFor Gin framework:\n  c.Header("Content-Security-Policy", "default-src \'self\'")\n\nValidate the policy with Google CSP Evaluator before deploying to production.'
)

write_rule('go', 'go_missing_xframe_options', RESEARCH_HEADER,
    issue='Missing X-Frame-Options header in Go net/http handler allows clickjacking',
    message='The Go HTTP application does not set the X-Frame-Options response header, permitting any external site to embed the application in an iframe. Attackers can exploit this to perform clickjacking, overlaying an invisible iframe on top of a legitimate-looking page to trick authenticated users into triggering unintended state-changing operations.',
    remediation='Set X-Frame-Options in a global Go HTTP middleware.\n\nUNSAFE: No X-Frame-Options header in HTTP response.\nSAFE:\n  func secureHeaders(next http.Handler) http.Handler {\n      return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n          w.Header().Set("X-Frame-Options", "DENY")\n          next.ServeHTTP(w, r)\n      })\n  }\n\nAlternatively use Content-Security-Policy frame-ancestors directive which is the modern standard.'
)

write_rule('go', 'go_missing_xcontent_type', RESEARCH_HEADER,
    issue='Missing X-Content-Type-Options header in Go net/http handler',
    message='The Go HTTP application does not set the X-Content-Type-Options: nosniff response header. Without this, browsers may override the declared MIME type and execute responses as a different content type. This significantly increases the risk of file upload vulnerabilities, as a browser might execute a malicious file served as text/plain as JavaScript code.',
    remediation='Set X-Content-Type-Options in all Go HTTP responses via a global middleware.\n\nUNSAFE: No X-Content-Type-Options header.\nSAFE:\n  w.Header().Set("X-Content-Type-Options", "nosniff")\n\nApply this in the outermost middleware so it applies to all routes including static file serving. The unrolled/secure package applies this automatically alongside other security headers.'
)

write_rule('go', 'go_gorilla_session_insecure', RESEARCH_SESSION,
    issue='Gorilla sessions configured without Secure or HttpOnly cookie attributes',
    cwe='CWE-16',
    message='The Go application uses gorilla/sessions without configuring the Secure and HttpOnly cookie options on the session store. A session cookie without the Secure flag can be sent over plain HTTP and intercepted. Without HttpOnly the session cookie is accessible to JavaScript code, making it vulnerable to theft via any XSS vulnerability in the application.',
    remediation='Configure gorilla/sessions with secure cookie options appropriate for production.\n\nUNSAFE:\n  store := sessions.NewCookieStore([]byte(os.Getenv("KEY")))\n\nSAFE:\n  store := sessions.NewCookieStore([]byte(os.Getenv("KEY")))\n  store.Options = &sessions.Options{\n      Path:     "/",\n      MaxAge:   86400,\n      HttpOnly: true,\n      Secure:   true,\n      SameSite: http.SameSiteStrictMode,\n  }\n\nSee OWASP Session Management Cheat Sheet for complete session cookie hardening guidance.'
)

# CSHARP (4 rules)
write_rule('csharp', 'csharp_missing_hsts', RESEARCH_HEADER,
    issue='Missing Strict-Transport-Security (HSTS) via UseHsts() in ASP.NET Core',
    message='The ASP.NET Core application does not call UseHsts() in its middleware pipeline, meaning the Strict-Transport-Security header is not sent to browsers. Without HSTS, browsers may connect over plain HTTP even when HTTPS is configured, leaving users vulnerable to man-in-the-middle attacks that can steal session tokens and credentials through SSL stripping.',
    remediation='Enable HSTS via UseHsts() and configure it with appropriate settings in ASP.NET Core.\n\nUNSAFE: No UseHsts() in the middleware pipeline.\nSAFE:\n  if (!app.Environment.IsDevelopment())\n  {\n      app.UseHsts();\n  }\n  builder.Services.AddHsts(opts => {\n      opts.MaxAge = TimeSpan.FromDays(365);\n      opts.IncludeSubDomains = true;\n  });\n\nAlso call app.UseHttpsRedirection() to force all HTTP traffic to HTTPS before HSTS enforcement.'
)

write_rule('csharp', 'csharp_missing_csp', RESEARCH_HEADER,
    issue='Missing Content-Security-Policy header in ASP.NET Core responses',
    message='The ASP.NET Core application does not configure a Content-Security-Policy response header. Without CSP, any XSS vulnerability has no browser-level restriction on script execution or resource loading. A successful XSS attack can steal session cookies, exfiltrate sensitive data via authenticated API requests, or inject malicious content that persists for all users.',
    remediation='Set a Content-Security-Policy header in ASP.NET Core via middleware.\n\nUNSAFE: No Content-Security-Policy header in the response pipeline.\nSAFE:\n  app.Use(async (context, next) => {\n      context.Response.Headers.Add(\n          "Content-Security-Policy",\n          "default-src \'self\'; script-src \'self\'");\n      await next();\n  });\n\nConsider the NWebSec NuGet package for a strongly-typed fluent security header configuration API.'
)

write_rule('csharp', 'csharp_missing_xframe_options', RESEARCH_HEADER,
    issue='Missing X-Frame-Options header in ASP.NET Core response allows clickjacking',
    message='The ASP.NET Core application does not set the X-Frame-Options response header, allowing the application to be embedded in an iframe by any third-party website. An attacker can exploit this with a clickjacking overlay to trick authenticated users into clicking hidden buttons, triggering unintended state-changing operations like form submissions or data deletions.',
    remediation='Set X-Frame-Options in ASP.NET Core middleware.\n\nUNSAFE: No X-Frame-Options header in the response pipeline.\nSAFE:\n  app.Use(async (context, next) => {\n      context.Response.Headers.Add("X-Frame-Options", "DENY");\n      await next();\n  });\n\nFor Razor Pages/MVC use a global filter or a centralized middleware. The Content-Security-Policy frame-ancestors directive is the modern alternative with more granular control.'
)

write_rule('csharp', 'csharp_missing_xcontent_type', RESEARCH_HEADER,
    issue='Missing X-Content-Type-Options header in ASP.NET Core response enables MIME sniffing',
    message='The ASP.NET Core application does not set the X-Content-Type-Options: nosniff response header. Without this protection, browsers may MIME-sniff response content and execute it as a different type than declared. When combined with file upload functionality, this can allow attackers to upload malicious files that the browser executes as JavaScript despite a safe declared MIME type.',
    remediation='Set X-Content-Type-Options in ASP.NET Core via middleware.\n\nUNSAFE: No X-Content-Type-Options header configured.\nSAFE:\n  app.Use(async (context, next) => {\n      context.Response.Headers.Add("X-Content-Type-Options", "nosniff");\n      await next();\n  });\n\nApply this globally across all routes. Consider consolidating all security headers into one middleware class for maintainability and consistent coverage.'
)

print('\nAll 30 rules written successfully!')
