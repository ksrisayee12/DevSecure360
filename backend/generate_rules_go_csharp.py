from rule_writer import write_rule

def gen_go_csharp_rules():
    # -------------------------------------------------------------
    # GO DEEP COVERAGE (11 RULES)
    # -------------------------------------------------------------
    
    # Go SQLi Variants
    write_rule(
        "go", "go_sqli_sqlx", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via sqlx",
        "The application uses the `sqlx` library to execute raw SQL queries that include unvalidated user input via string concatenation or formatting, leading to SQL injection.",
        [],
        ["sqlx.Get(", "sqlx.Select(", "sqlx.Exec("],
        [],
        "Use parameterized queries provided by the `sqlx` library (e.g., using `?` placeholders or named parameters) instead of string concatenation."
    )

    write_rule(
        "go", "go_sqli_pgx", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via pgx",
        "The application uses the `pgx` library for PostgreSQL to execute queries constructed with user input via string concatenation, bypassing parameterization.",
        [],
        ["pgx.Conn.Exec(", "pgx.Pool.Query("],
        [],
        "Use parameterized queries (e.g., `$1`, `$2` placeholders) which are fully supported and recommended by the `pgx` driver."
    )

    write_rule(
        "go", "go_sqli_gorm_raw", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via gorm Raw/Where",
        "The application uses GORM's `Raw()` or `Where()` methods with format strings or concatenation to inject user data, rendering ORM protections ineffective.",
        [],
        ["gorm.DB.Raw(", "gorm.DB.Where("],
        [],
        "Pass user input as additional arguments to `Raw()` or `Where()` to utilize GORM's built-in parameter binding."
    )

    # Go CMDi Variants
    write_rule(
        "go", "go_cmdi_shell_dash_c", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via sh -c",
        "The application invokes a shell (`sh -c`) using `os/exec.Command` and passes user-controlled input as part of the command string.",
        [],
        ["exec.Command(\"sh\", \"-c\""],
        [],
        "Avoid invoking intermediate shells (`sh`). Execute the target binary directly with arguments passed as separate items in the `exec.Command` variadic parameter list."
    )

    write_rule(
        "go", "go_cmdi_bash_dash_c", "CMDi", "Critical", "CWE-78", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Command Injection via bash -c",
        "The application invokes a shell (`bash -c`) using `os/exec.Command` and passes user-controlled input as part of the command string.",
        [],
        ["exec.Command(\"bash\", \"-c\""],
        [],
        "Avoid invoking intermediate shells (`bash`). Execute the target binary directly with arguments passed as separate items in the `exec.Command` variadic parameter list."
    )

    # Go Path Traversal Variants
    write_rule(
        "go", "go_path_traversal_os", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via os package",
        "The application passes user input directly to `os` package file operations (e.g., `os.Open`, `os.ReadFile`), allowing attackers to read or write arbitrary files on the filesystem.",
        [],
        ["os.Open(", "os.ReadFile(", "os.WriteFile("],
        [],
        "Sanitize user input using `filepath.Clean()` and ensure the resulting path remains within the intended, restricted directory scope before passing it to `os` functions."
    )

    write_rule(
        "go", "go_path_traversal_http", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via http.ServeFile",
        "The application serves files using `http.ServeFile` or `http.Dir` with user-controlled paths, which can expose arbitrary files outside the web root if not properly validated.",
        [],
        ["http.ServeFile(", "http.Dir("],
        [],
        "Ensure paths provided to `http.ServeFile` are strongly validated, restricted to safe directories, and cannot contain directory traversal characters."
    )

    write_rule(
        "go", "go_path_traversal_ioutil", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via ioutil package",
        "The application passes user input to deprecated but common `ioutil` package functions (e.g., `ioutil.ReadFile`), enabling path traversal.",
        [],
        ["ioutil.ReadFile(", "ioutil.WriteFile("],
        [],
        "Sanitize inputs using `filepath.Clean()` and ensure the path resolves within the allowed directory before calling `ioutil` (or the newer `os`) equivalents."
    )

    # Go SSRF Variants
    write_rule(
        "go", "go_ssrf_default_client", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "Confirmed",
        "SSRF via Default HTTP Client",
        "The application fetches resources based on user input using the default HTTP client (`http.Get`, `http.Post`), allowing attackers to force requests to internal or external systems.",
        [],
        ["http.Get(", "http.Post(", "http.Head("],
        [],
        "Use an allowlist of permitted domains or configure a custom HTTP client that explicitly blocks requests to private/internal IP address ranges."
    )

    write_rule(
        "go", "go_ssrf_custom_client", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "Confirmed",
        "SSRF via Custom HTTP Client",
        "The application fetches resources based on user input using a custom HTTP client (`client.Do`, `client.Get`), creating an SSRF vulnerability.",
        [],
        ["client.Get(", "client.Do(", "client.Post("],
        [],
        "Validate user-provided URLs against a strict allowlist or configure the `Transport` layer to deny resolutions to internal/loopback IP addresses."
    )

    write_rule(
        "go", "go_ssrf_url_parse", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "Tentative",
        "SSRF vector via url.Parse",
        "The application parses user input using `url.Parse()` which is subsequently used to build HTTP requests, posing a risk of Server-Side Request Forgery.",
        [],
        ["url.Parse("],
        [],
        "Thoroughly validate the parsed URL components (Scheme and Host) against an allowlist before using the resulting object in outbound network requests."
    )

    # -------------------------------------------------------------
    # C# DEEP COVERAGE (14 RULES)
    # -------------------------------------------------------------

    # C# SQLi Variants
    write_rule(
        "csharp", "csharp_sqli_dapper", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via Dapper",
        "The application uses Dapper ORM methods (`connection.Query`, `connection.Execute`) with dynamically concatenated SQL query strings containing untrusted data.",
        [],
        ["connection.Query(", "connection.Execute("],
        [],
        "Use Dapper's parameterized query support by passing an anonymous object containing the parameters (e.g., `connection.Query(sql, new { id = userInput })`)."
    )

    write_rule(
        "csharp", "csharp_sqli_adonet", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via ADO.NET SqlCommand",
        "The application creates a new `SqlCommand` using a query string constructed via string concatenation with user input, bypassing parameterization.",
        [],
        ["new SqlCommand("],
        [],
        "Always use `SqlCommand.Parameters.Add()` or `AddWithValue()` to bind user input to the query safely, avoiding string interpolation or concatenation."
    )

    write_rule(
        "csharp", "csharp_sqli_oledb", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via OleDbCommand",
        "The application creates a new `OleDbCommand` using a dynamically built query string, leading to SQL injection.",
        [],
        ["new OleDbCommand("],
        [],
        "Always utilize parameterized queries by adding parameters to the `OleDbCommand.Parameters` collection instead of directly formatting strings."
    )

    write_rule(
        "csharp", "csharp_sqli_npgsql", "SQLi", "Critical", "CWE-89", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "SQL Injection via NpgsqlCommand",
        "The application constructs queries for PostgreSQL using `NpgsqlCommand` and string concatenation, allowing attackers to inject arbitrary SQL statements.",
        [],
        ["new NpgsqlCommand("],
        [],
        "Bind user input to the database query by adding elements to the `NpgsqlCommand.Parameters` collection to ensure safe query execution."
    )

    # C# Path Traversal Variants
    write_rule(
        "csharp", "csharp_path_file_info", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via FileInfo",
        "The application instantiates `FileInfo` using unvalidated user input for the file path, potentially granting access to unauthorized files.",
        [],
        ["new FileInfo("],
        [],
        "Validate user-provided paths by checking them against an allowlist, or use `Path.GetFullPath()` and verify it starts with an expected base directory."
    )

    write_rule(
        "csharp", "csharp_path_directory", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via Directory Methods",
        "The application reads directory contents using `Directory.GetFiles` or `Directory.EnumerateFiles` with user-supplied path data.",
        [],
        ["Directory.GetFiles(", "Directory.EnumerateFiles("],
        [],
        "Ensure the path resolves to a safe directory by validating its absolute path (`Path.GetFullPath`) against an expected root directory string."
    )

    write_rule(
        "csharp", "csharp_path_stream", "Path Traversal", "High", "CWE-22", "A01:2021-Broken Access Control", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Confirmed",
        "Path Traversal via FileStream/StreamReader",
        "The application performs I/O operations by passing user-supplied paths to `FileStream`, `StreamReader`, or `StreamWriter` constructors without adequate validation.",
        [],
        ["new FileStream(", "new StreamReader(", "new StreamWriter("],
        [],
        "Sanitize and validate paths strictly. Verify the normalized absolute path matches the intended restricted base path to prevent directory climbing (`../`)."
    )

    # C# Deserialization Variants
    write_rule(
        "csharp", "csharp_deser_newtonsoft", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via Newtonsoft TypeNameHandling",
        "The application uses Newtonsoft.Json (`JsonConvert.DeserializeObject`) with `TypeNameHandling.All` or `Auto` along with untrusted data, leading to remote code execution.",
        [],
        ["JsonConvert.DeserializeObject("],
        [],
        "Configure `TypeNameHandling` to `None`. If polymorphism is strictly required, implement and apply a rigorous `ISerializationBinder` to restrict permissible types."
    )

    write_rule(
        "csharp", "csharp_deser_binaryformatter", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Insecure Deserialization via BinaryFormatter",
        "The application deserializes untrusted data using the dangerous `BinaryFormatter` class. This class is fundamentally insecure and cannot be made safe.",
        [],
        ["BinaryFormatter.Deserialize("],
        [],
        "Completely remove `BinaryFormatter`. Migrate to a safe deserialization library such as `System.Text.Json`."
    )

    write_rule(
        "csharp", "csharp_deser_xmlserializer", "Deserialization", "Critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Insecure Deserialization via XmlSerializer",
        "The application uses `XmlSerializer` to deserialize XML data while allowing arbitrary types to be loaded, posing a risk of insecure deserialization.",
        [],
        ["XmlSerializer.Deserialize("],
        [],
        "Avoid resolving arbitrary types during XML deserialization. Use strongly-typed wrapper classes and restrict resolving external XML entities."
    )

    # C# XSS Variants
    write_rule(
        "csharp", "csharp_xss_razor", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "XSS via Html.Raw in Razor",
        "The application outputs unencoded user input in a Razor view using `@Html.Raw()`, which overrides default encoding protections and leads to Cross-Site Scripting.",
        [],
        ["@Html.Raw("],
        [],
        "Avoid using `@Html.Raw()` with user-supplied data. Rely on the default auto-encoding of Razor views by using standard `@variable` syntax."
    )

    write_rule(
        "csharp", "csharp_xss_response_write", "XSS", "High", "CWE-79", "A03:2021-Injection", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Confirmed",
        "XSS via Response.Write",
        "The application writes unencoded user data directly to the HTTP response using `Response.Write()`, exposing users to XSS attacks.",
        [],
        ["Response.Write("],
        [],
        "Always HTML-encode user input using `HttpUtility.HtmlEncode()` or `HtmlEncoder.Default.Encode()` before writing it directly to the response stream."
    )

    # C# SSRF Variants
    write_rule(
        "csharp", "csharp_ssrf_webclient", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "Confirmed",
        "SSRF via WebClient or WebRequest",
        "The application uses older classes like `WebClient` or `WebRequest` to make outbound network requests using unvalidated user input for the URL.",
        [],
        ["new WebClient(", "WebRequest.Create("],
        [],
        "Validate the requested URL against an explicit allowlist before fetching resources. Restrict requests to trusted, non-internal IPs."
    )

    write_rule(
        "csharp", "csharp_ssrf_httpclient", "SSRF", "High", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "Confirmed",
        "SSRF via HttpClient",
        "The application uses `HttpClient` to execute HTTP methods (GetAsync, PostAsync) where the target URL is constructed using untrusted user input.",
        [],
        ["HttpClient.GetAsync(", "HttpClient.PostAsync("],
        [],
        "Perform strict domain or IP validation using an allowlist before passing the URL to `HttpClient` methods. Do not permit resolutions to private networks."
    )

if __name__ == '__main__':
    gen_go_csharp_rules()
