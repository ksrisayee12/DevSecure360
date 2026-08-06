"""
generate_batch12.py — Balanced Expansion: 5 rules × 8 languages = 40 rules
Diverse CVE categories: Zip Slip, Timing Attack, EL Injection, GraphQL,
CSV Injection, HTTP Response Splitting, Memory Safety variants, etc.
Every language treated equally.
"""
import os, yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "scanner", "sast", "rules")


class LS(str):
    pass


def lp(d, data):
    return d.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LS, lp)


def wr(lang, rid, res, vc, cwe, owasp, cvss, cvss_v, sev, conf, issue, msg, sources, sinks, sans, rem):
    d = os.path.join(RULES_DIR, lang)
    os.makedirs(d, exist_ok=True)
    rule = {
        "rule_id": rid, "language": lang, "vuln_class": vc,
        "severity": sev, "cwe": cwe, "owasp": owasp,
        "cvss_score": cvss, "cvss_vector": cvss_v, "confidence": conf,
        "issue": issue, "message": LS(msg.strip()),
        "sources": sources, "sinks": sinks, "sanitizers": sans,
        "remediation": LS(rem.strip()),
    }
    content = res.strip() + "\n\n" + yaml.dump(rule, default_flow_style=False, allow_unicode=True, sort_keys=False)
    open(os.path.join(d, rid + ".yaml"), "w", encoding="utf-8").write(content)
    print("Written: " + rid)


# ── Research blocks ──────────────────────────────────────────────────────────
RE = {
    "zip_slip": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/22.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=zip+slip\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html\n"
        "# Verification:    Zip-slip path traversal via archive entry names verified from Snyk Research (2018) and CodeQL."
    ),
    "timing": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/208.html\n"
        "# CodeQL Source:   Not applicable — pattern-based comparison detection\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=timing+attack\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html\n"
        "# Verification:    Non-constant-time comparison for cryptographic secrets detected structurally. Rule is Tentative."
    ),
    "el_inj": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/94.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/java/\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=expression+language+injection\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html\n"
        "# Verification:    Spring EL and Roslyn expression evaluation sinks verified from CodeQL and Semgrep registry."
    ),
    "graphql": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/943.html\n"
        "# CodeQL Source:   Not applicable — pattern-based query string detection\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=graphql+injection\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html\n"
        "# Verification:    GraphQL query string concatenation sinks verified from OWASP GraphQL Cheat Sheet and Semgrep."
    ),
    "csv_inj": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/1236.html\n"
        "# CodeQL Source:   Not applicable — pattern-based formula character detection\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=csv+injection\n"
        "# OWASP Cheat:     https://owasp.org/www-community/attacks/CSV_Injection\n"
        "# Verification:    CSV formula injection (=,+,@,-) detected as pattern-based code injection. Rule is Tentative."
    ),
    "resp_split": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/113.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=http+response+splitting\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Reference_Cheat_Sheet.html\n"
        "# Verification:    HTTP response splitting via unvalidated header values verified from CodeQL and Semgrep registry."
    ),
    "mem_c": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/415.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
        "# Semgrep Source:  Not applicable — CFG-based memory analysis\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
        "# Verification:    Double-free, dangling pointer, and virtual dispatch UAF patterns from CodeQL C/C++ libraries."
    ),
    "race_c": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/362.html\n"
        "# CodeQL Source:   Not applicable — structural pattern detection\n"
        "# Semgrep Source:  Not applicable — CFG-based TOCTOU detection\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
        "# Verification:    Signal handler and TOCTOU race patterns verified from CWE-362 and CERT C Coding Standard."
    ),
    "bof_c": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/122.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=heap+overflow\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
        "# Verification:    Heap overflow via malloc+memcpy without bounds verified from CodeQL C/C++ standard libraries."
    ),
    "cmdi_env": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/78.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
        "# Semgrep Source:  https://semgrep.dev/r?q=command+injection+environment\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html\n"
        "# Verification:    getenv() result passed to system/execvp command execution sinks from CodeQL and Semgrep."
    ),
    "cpp_mem": (
        "# RESEARCH EVIDENCE\n"
        "# CWE Source:      https://cwe.mitre.org/data/definitions/119.html\n"
        "# CodeQL Source:   https://codeql.github.com/codeql-standard-libraries/cpp/\n"
        "# Semgrep Source:  Not applicable — static analysis CFG patterns\n"
        "# OWASP Cheat:     https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html\n"
        "# Verification:    C++ memory safety patterns (dangling, uninit, reinterpret_cast) from CodeQL C++ standard libraries."
    ),
}

# ── Source lists ─────────────────────────────────────────────────────────────
JAVA_SRC = ["request.getParameter(", "request.getHeader(", "@RequestParam", "@PathVariable", "@RequestBody"]
JS_SRC   = ["req.body", "req.query", "req.params", "req.headers", "req.cookies"]
PY_SRC   = ["request.args", "request.form", "request.data", "request.json", "request.files"]
GO_SRC   = ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "r.Body"]
CS_SRC   = ["Request.Query[", "Request.Form[", "Request.Headers[", "HttpContext.Request"]
PHP_SRC  = ["$_GET[", "$_POST[", "$_REQUEST[", "$_FILES[", "$_COOKIE["]

# ════════════════════════════════════════════════════════════════════════════
# C — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("c", "c_double_free", RE["mem_c"],
   "Use After Free", "CWE-415", "A06:2021-Vulnerable and Outdated Components",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "High", "Tentative",
   "Double-free vulnerability: memory freed twice, enabling heap corruption and code execution",
   ("The same heap pointer is passed to free() more than once without being set to NULL after the "
    "first free. A double-free corrupts the heap allocator's internal bookkeeping structures. "
    "An attacker who can trigger the double-free can use it to achieve arbitrary write primitives "
    "on modern glibc allocators, leading to remote code execution or privilege escalation."),
   [], ["free("], ["NULL after free"],
   ("Set the pointer to NULL immediately after every free() call to prevent double-free.\n\n"
    "UNSAFE:\n"
    "  free(ptr);\n"
    "  /* ... other code ... */\n"
    "  free(ptr);  /* double-free */\n\n"
    "SAFE:\n"
    "  free(ptr);\n"
    "  ptr = NULL;  /* prevents double-free */\n\n"
    "Use AddressSanitizer (-fsanitize=address) during development to detect double-free at runtime. "
    "See CERT MEM31-C: Free dynamically allocated memory exactly once.")
)

wr("c", "c_signal_handler_async_unsafe", RE["race_c"],
   "Race Condition", "CWE-364", "A06:2021-Vulnerable and Outdated Components",
   6.4, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", "High", "Tentative",
   "Async-signal-unsafe function called inside signal handler — race condition risk",
   ("A signal handler calls functions that are not async-signal-safe (e.g., malloc, free, printf, "
    "syslog). Signal handlers can interrupt any code at any point. If the main program is inside "
    "a non-reentrant function (like malloc) when the signal fires, calling the same function from "
    "the handler causes heap corruption, deadlock, or undefined behavior exploitable by attackers."),
   [], ["signal(", "sigaction("], ["sig_atomic_t", "async-signal-safe"],
   ("Only call async-signal-safe functions from signal handlers. Set a flag and handle work in main.\n\n"
    "UNSAFE:\n"
    "  void handler(int sig) {\n"
    "      printf(\"Signal received\");  /* not async-signal-safe */\n"
    "      free(global_buf);           /* not async-signal-safe */\n"
    "  }\n\n"
    "SAFE:\n"
    "  volatile sig_atomic_t signal_received = 0;\n"
    "  void handler(int sig) { signal_received = 1; }  /* only set flag */\n"
    "  /* Check flag and handle in main loop */\n\n"
    "See POSIX async-signal-safe function list and CERT SIG30-C for complete guidance.")
)

wr("c", "c_toctou_file", RE["race_c"],
   "Race Condition", "CWE-367", "A01:2021-Broken Access Control",
   6.3, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", "High", "Tentative",
   "TOCTOU race: checking file access with access() then opening with open() allows symlink attacks",
   ("The program checks file accessibility with access() and then opens the file with open(). "
    "Between the check (Time-Of-Check) and the use (Time-Of-Use) an attacker can replace the "
    "target file with a symlink to a sensitive file (e.g., /etc/shadow). The program then opens "
    "the attacker's symlink with elevated privileges, bypassing the intended access check."),
   [], ["access(", "faccessat("], ["O_NOFOLLOW"],
   ("Eliminate the TOCTOU window by opening the file directly and checking the result atomically.\n\n"
    "UNSAFE:\n"
    "  if (access(path, R_OK) == 0) {\n"
    "      fd = open(path, O_RDONLY);  /* race window here */\n"
    "  }\n\n"
    "SAFE:\n"
    "  fd = open(path, O_RDONLY | O_NOFOLLOW);  /* atomic, no symlink follow */\n"
    "  if (fd < 0) { /* handle error */ }\n\n"
    "Use O_NOFOLLOW to reject symlinks. Run with minimal privileges. See CERT FIO45-C.")
)

wr("c", "c_heap_overflow", RE["bof_c"],
   "Buffer Overflow", "CWE-122", "A06:2021-Vulnerable and Outdated Components",
   8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "High", "Tentative",
   "Heap buffer overflow: malloc allocated with user-controlled size then written past bounds",
   ("A buffer is allocated with malloc() using a size derived from user-controlled input without "
    "overflow validation. A subsequent memcpy() or write operation copies more data than fits in "
    "the allocated region. Heap overflows corrupt adjacent heap chunks, enabling attackers to "
    "overwrite function pointers, GOT entries, or other heap metadata to gain code execution."),
   [], ["malloc(", "calloc(", "realloc("], ["size_t overflow check", "SAFE_MALLOC"],
   ("Validate size parameters for arithmetic overflow before passing to malloc, and bounds-check writes.\n\n"
    "UNSAFE:\n"
    "  size_t size = user_len * sizeof(int);  /* may overflow */\n"
    "  int *buf = malloc(size);\n"
    "  memcpy(buf, src, user_len * sizeof(int));  /* no bounds check */\n\n"
    "SAFE:\n"
    "  if (user_len > SIZE_MAX / sizeof(int)) return ERROR;\n"
    "  size_t size = user_len * sizeof(int);\n"
    "  int *buf = malloc(size);\n"
    "  if (!buf) return ERROR;\n"
    "  memcpy(buf, src, size);\n\n"
    "Use reallocarray() which checks overflow. See CERT MEM35-C.")
)

wr("c", "c_env_cmdi", RE["cmdi_env"],
   "CMDi", "CWE-78", "A03:2021-Injection",
   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Confirmed",
   "Command Injection via user-controlled environment variable passed to system() or execvp()",
   ("The program reads a value from the environment using getenv() and passes it unsanitized to "
    "system(), popen(), or execvp(). An attacker who can control environment variables (via CGI, "
    "container environments, or privilege escalation) can inject arbitrary shell commands. "
    "This pattern is particularly dangerous in setuid programs where the attacker controls the env."),
   ["getenv(", "secure_getenv("], ["system(", "popen(", "execvp(", "execl("], ["escapeshellarg"],
   ("Never pass environment variable values directly to shell execution. Validate against allowlist.\n\n"
    "UNSAFE:\n"
    "  char *path = getenv(\"USER_PATH\");\n"
    "  system(path);  /* attacker controls USER_PATH */\n\n"
    "SAFE:\n"
    "  char *path = getenv(\"USER_PATH\");\n"
    "  if (!is_safe_path(path)) exit(1);\n"
    "  execv(safe_binary, safe_args);  /* not system() */\n\n"
    "Unset dangerous env vars (PATH, LD_PRELOAD, IFS) in setuid programs. See CERT ENV33-C.")
)

# ════════════════════════════════════════════════════════════════════════════
# C++ — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("cpp", "cpp_dangling_iterator", RE["cpp_mem"],
   "Use After Free", "CWE-416", "A06:2021-Vulnerable and Outdated Components",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "High", "Tentative",
   "Use-After-Free via STL iterator invalidation: iterator used after container mutation",
   ("An iterator to a standard library container (vector, deque, unordered_map) is stored and "
    "then used after an operation that invalidates it (push_back, erase, insert, rehash). "
    "The iterator points to freed or reallocated memory. Dereferencing it is undefined behavior, "
    "exploitable to read heap data or redirect control flow on hardened systems."),
   [], ["push_back(", ".insert(", ".erase(", ".clear(", ".resize("], ["std::distance", ".end()"],
   ("Re-acquire iterators after any mutating container operation. Use indices for stable references.\n\n"
    "UNSAFE:\n"
    "  auto it = vec.begin();\n"
    "  vec.push_back(42);  /* invalidates all iterators */\n"
    "  *it = 0;            /* dangling iterator — UB */\n\n"
    "SAFE:\n"
    "  size_t idx = std::distance(vec.begin(), it);  /* save index */\n"
    "  vec.push_back(42);\n"
    "  vec[idx] = 0;  /* use index, not iterator */\n\n"
    "Use iterator invalidation rules from the C++ standard. Consider span<> for stable views.")
)

wr("cpp", "cpp_uninitialized_memory_read", RE["cpp_mem"],
   "Memory Corruption", "CWE-457", "A06:2021-Vulnerable and Outdated Components",
   5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Memory Corruption via use of uninitialized local variable or stack memory",
   ("A local variable or struct field is declared but not initialized before being read or returned. "
    "Reading uninitialized stack memory exposes sensitive data from previous stack frames, including "
    "passwords, keys, and pointers. On Linux, partial ASLR bypass is possible by leaking stack "
    "pointer values through uninitialized struct members returned to user-space callers."),
   [], ["int ", "char ", "struct "], ["= 0", "memset(", "= {}"],
   ("Always initialize local variables and struct members at declaration. Use value-initialization.\n\n"
    "UNSAFE:\n"
    "  int result;  /* uninitialized */\n"
    "  if (condition) result = compute();\n"
    "  return result;  /* may be garbage */\n\n"
    "SAFE:\n"
    "  int result = 0;  /* initialized */\n"
    "  if (condition) result = compute();\n"
    "  return result;\n\n"
    "Build with -Wuninitialized -Wall. Use Valgrind/Memcheck. See CERT EXP33-C.")
)

wr("cpp", "cpp_virtual_dispatch_freed", RE["mem_c"],
   "Use After Free", "CWE-416", "A06:2021-Vulnerable and Outdated Components",
   8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "High", "Tentative",
   "Use-After-Free via virtual method dispatch on deleted/freed C++ object",
   ("A virtual method is called on a pointer or reference to an object that has already been "
    "deleted. The vtable pointer in the freed memory may have been overwritten by a subsequent "
    "allocation. An attacker who controls heap layout can plant a fake vtable pointer at the "
    "freed location and redirect execution to arbitrary code when the virtual call is dispatched."),
   [], ["delete ", "free("], ["nullptr check", "shared_ptr"],
   ("Use RAII and smart pointers to ensure objects are not used after deletion.\n\n"
    "UNSAFE:\n"
    "  Base *obj = new Derived();\n"
    "  delete obj;\n"
    "  obj->virtualMethod();  /* UAF — obj points to freed memory */\n\n"
    "SAFE:\n"
    "  std::unique_ptr<Base> obj = std::make_unique<Derived>();\n"
    "  /* obj automatically deleted at scope exit, cannot be used after */\n\n"
    "Enable -D_GLIBCXX_DEBUG and AddressSanitizer for runtime detection. See CERT MEM50-CPP.")
)

wr("cpp", "cpp_stack_vla_overflow", RE["bof_c"],
   "Buffer Overflow", "CWE-121", "A06:2021-Vulnerable and Outdated Components",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "High", "Tentative",
   "Stack buffer overflow via Variable-Length Array (VLA) with unchecked user-controlled size",
   ("A Variable-Length Array is declared on the stack with a size derived from user-controlled "
    "input without a maximum-size check. An attacker providing an extremely large size causes "
    "a stack overflow by allocating more stack space than available. This overwrites the return "
    "address or frame pointers, potentially enabling code execution via ROP or ret2libc."),
   [], ["char buf[n]", "int arr[n]", "alloca("], ["MAX_SIZE", "< MAX"],
   ("Replace VLAs with statically sized arrays or heap allocation with bounds checking.\n\n"
    "UNSAFE:\n"
    "  void process(size_t n) {\n"
    "      char buf[n];  /* VLA — no upper bound check */\n"
    "  }\n\n"
    "SAFE:\n"
    "  void process(size_t n) {\n"
    "      if (n > MAX_BUF_SIZE) return;  /* bounds check first */\n"
    "      char *buf = malloc(n);          /* heap instead of stack */\n"
    "  }\n\n"
    "VLAs were made optional in C11 and C++14 removed them. Enable -Wvla. See CERT ARR32-C.")
)

wr("cpp", "cpp_reinterpret_cast_misuse", RE["cpp_mem"],
   "Memory Corruption", "CWE-704", "A06:2021-Vulnerable and Outdated Components",
   6.7, "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "Medium", "Tentative",
   "Memory Corruption via unsafe reinterpret_cast between unrelated pointer types (type punning)",
   ("A reinterpret_cast is used to convert a pointer of one type directly to an unrelated type "
    "without using a union or memcpy, violating strict aliasing rules. The compiler may generate "
    "incorrect code because it assumes aliased pointers of different types never point to the same "
    "memory. This leads to incorrect reads, corrupted writes, and undefined behavior."),
   [], ["reinterpret_cast<"], ["memcpy(", "std::bit_cast<"],
   ("Use memcpy() or std::bit_cast<> (C++20) for type punning instead of reinterpret_cast.\n\n"
    "UNSAFE:\n"
    "  float f = 3.14f;\n"
    "  int i = *reinterpret_cast<int*>(&f);  /* strict aliasing violation — UB */\n\n"
    "SAFE (C++20):\n"
    "  float f = 3.14f;\n"
    "  int i = std::bit_cast<int>(f);  /* defined behavior */\n\n"
    "SAFE (pre-C++20):\n"
    "  float f = 3.14f;\n"
    "  int i;\n"
    "  memcpy(&i, &f, sizeof(i));  /* defined behavior */\n\n"
    "Build with -fstrict-aliasing -Wstrict-aliasing. See GCC aliasing documentation.")
)

# ════════════════════════════════════════════════════════════════════════════
# Go — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("go", "go_zip_slip", RE["zip_slip"],
   "Path Traversal", "CWE-22", "A01:2021-Broken Access Control",
   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "Zip Slip path traversal via archive/zip entry with ../ in filename written to disk",
   ("The application extracts a ZIP archive using archive/zip without validating that each entry's "
    "Name field stays within the intended extraction directory. An attacker can craft a ZIP file "
    "with entries named like ../../etc/cron.d/evil or ../../.ssh/authorized_keys, causing files to "
    "be written outside the target directory — potentially overwriting system files or config."),
   GO_SRC,
   ["zipReader.Open(", "rc.Name", "os.Create(", "ioutil.WriteFile("],
   ["filepath.Clean(", "filepath.Rel(", "strings.HasPrefix("],
   ("Validate each archive entry name against the extraction base path before writing.\n\n"
    "UNSAFE:\n"
    "  for _, f := range r.File {\n"
    "      os.Create(filepath.Join(dest, f.Name))  /* f.Name may contain ../ */\n"
    "  }\n\n"
    "SAFE:\n"
    "  for _, f := range r.File {\n"
    "      target := filepath.Join(dest, f.Name)\n"
    "      if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) {\n"
    "          return fmt.Errorf(\"zip slip detected: %s\", f.Name)\n"
    "      }\n"
    "      os.Create(target)\n"
    "  }\n\n"
    "See Snyk Zip Slip Vulnerability research and OWASP File Upload Cheat Sheet.")
)

wr("go", "go_timing_attack", RE["timing"],
   "Weak Crypto", "CWE-208", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Timing attack: non-constant-time comparison of HMAC or security token with bytes.Equal()",
   ("The application uses bytes.Equal() or simple == comparison to verify HMACs, session tokens, "
    "or API keys. Go's bytes.Equal() short-circuits on the first differing byte, leaking the "
    "comparison duration via network timing. An attacker making millions of requests can statistically "
    "determine correct token bytes one at a time, forging valid HMAC signatures or tokens."),
   GO_SRC,
   ["bytes.Equal(", "== string("],
   ["hmac.Equal(", "subtle.ConstantTimeCompare("],
   ("Use crypto/subtle.ConstantTimeCompare() or hmac.Equal() for all HMAC and security token checks.\n\n"
    "UNSAFE:\n"
    "  if bytes.Equal(providedMAC, expectedMAC) { /* timing leak */ }\n"
    "  if token == expectedToken { /* timing leak */ }\n\n"
    "SAFE:\n"
    "  import \"crypto/subtle\"\n"
    "  if subtle.ConstantTimeCompare(providedMAC, expectedMAC) == 1 { /* OK */ }\n"
    "  // For HMAC specifically:\n"
    "  import \"crypto/hmac\"\n"
    "  if hmac.Equal(providedMAC, expectedMAC) { /* OK */ }\n\n"
    "See Go crypto/subtle package docs and OWASP Cryptographic Storage Cheat Sheet.")
)

wr("go", "go_html_unsafe_escape", RE["resp_split"],
   "XSS", "CWE-79", "A03:2021-Injection",
   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "High", "Confirmed",
   "XSS via Go html/template.HTML() type bypassing auto-escaping of user-controlled content",
   ("The application wraps user-controlled data with template.HTML(), template.JS(), or template.URL() "
    "and passes it to an html/template rendering context. These types explicitly mark content as "
    "safe, bypassing the auto-escaping that html/template provides. An attacker who controls the "
    "wrapped value can inject arbitrary HTML and JavaScript into the rendered page."),
   GO_SRC,
   ["template.HTML(", "template.JS(", "template.URL(", "template.CSS("],
   ["html.EscapeString(", "template.HTMLEscapeString("],
   ("Never wrap user-controlled input with template.HTML() or similar unsafe types.\n\n"
    "UNSAFE:\n"
    "  data := template.HTML(r.FormValue(\"content\"))  /* bypasses escaping */\n\n"
    "SAFE:\n"
    "  data := r.FormValue(\"content\")  /* passed as string, auto-escaped by template engine */\n\n"
    "html/template auto-escapes string values by context. Only use template.HTML() for "
    "server-generated HTML that you explicitly trust. See OWASP XSS Prevention Cheat Sheet.")
)

wr("go", "go_env_cmdi", RE["cmdi_env"],
   "CMDi", "CWE-78", "A03:2021-Injection",
   8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "High", "Confirmed",
   "Command Injection via os.Getenv() result passed to exec.Command without sanitization",
   ("An environment variable read with os.Getenv() is passed directly as an argument to "
    "exec.Command() or exec.CommandContext() without validation. In containerized environments, "
    "microservices, or CGI handlers, attackers may control environment variables. If the env var "
    "is used to build shell commands, arbitrary command injection is possible."),
   ["os.Getenv(", "os.LookupEnv("],
   ["exec.Command(", "exec.CommandContext("],
   ["path.Clean(", "allowlist"],
   ("Validate environment variable values against a strict allowlist before using in exec.Command.\n\n"
    "UNSAFE:\n"
    "  cmd := exec.Command(\"convert\", os.Getenv(\"INPUT_FILE\"), \"output.png\")\n\n"
    "SAFE:\n"
    "  inputFile := os.Getenv(\"INPUT_FILE\")\n"
    "  if !isAllowedFilePath(inputFile) {\n"
    "      log.Fatal(\"Invalid INPUT_FILE\")\n"
    "  }\n"
    "  cmd := exec.Command(\"convert\", inputFile, \"output.png\")\n\n"
    "Prefer exec.Command with argument arrays (no shell). See OWASP OS Command Injection Defense Cheat Sheet.")
)

wr("go", "go_nosqli_bson", RE["graphql"],
   "NoSQLi", "CWE-943", "A03:2021-Injection",
   8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "NoSQL Injection via MongoDB bson.D or bson.M filter with user-controlled operator fields",
   ("User-controlled input is used directly to construct a MongoDB bson.D or bson.M query filter "
    "without sanitizing the field keys or values. An attacker can inject MongoDB operators like "
    "$gt, $where, $regex, or $ne by controlling the filter key names, causing the query to return "
    "unauthorized documents or bypass authentication checks entirely."),
   GO_SRC,
   ["bson.D{", "bson.M{", "collection.Find(", "collection.FindOne("],
   ["primitive.ObjectIDFromHex(", "regexp.MustCompile("],
   ("Use typed, structured filter documents — never allow user input to control field key names.\n\n"
    "UNSAFE:\n"
    "  filter := bson.M{userKey: userValue}  /* userKey could be '$where' */\n\n"
    "SAFE:\n"
    "  // Hardcode the field name; only accept the value from user\n"
    "  filter := bson.M{\"username\": sanitizedUsername, \"active\": true}\n\n"
    "Validate and sanitize all values. Never let user input control MongoDB operator key names. "
    "See OWASP NoSQL Injection Prevention guidance.")
)

# ════════════════════════════════════════════════════════════════════════════
# C# — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("csharp", "csharp_zip_slip", RE["zip_slip"],
   "Path Traversal", "CWE-22", "A01:2021-Broken Access Control",
   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "Zip Slip path traversal via ZipArchiveEntry with ../ in FullName extracted to disk",
   ("The application extracts ZIP archive entries using ZipArchive/ZipArchiveEntry without "
    "validating that each entry's FullName remains within the intended extraction directory. "
    "An attacker can craft a ZIP with entries like ../../appsettings.json or C:\\Windows\\System32\\evil.dll, "
    "causing files to be written to arbitrary locations on the server filesystem."),
   CS_SRC,
   ["entry.FullName", "ZipFile.ExtractToDirectory(", "entry.ExtractToFile("],
   ["Path.GetFullPath(", "Path.Combine(destinationPath"],
   ("Validate each entry's destination path against the extraction root before writing.\n\n"
    "UNSAFE:\n"
    "  foreach (var entry in archive.Entries)\n"
    "      entry.ExtractToFile(Path.Combine(destDir, entry.FullName));\n\n"
    "SAFE:\n"
    "  foreach (var entry in archive.Entries) {\n"
    "      string dest = Path.GetFullPath(Path.Combine(destDir, entry.FullName));\n"
    "      if (!dest.StartsWith(Path.GetFullPath(destDir), StringComparison.OrdinalIgnoreCase))\n"
    "          throw new SecurityException(\"Zip Slip detected\");\n"
    "      entry.ExtractToFile(dest);\n"
    "  }\n\n"
    "See Snyk Zip Slip research and OWASP Path Traversal defense guide.")
)

wr("csharp", "csharp_timing_attack", RE["timing"],
   "Weak Crypto", "CWE-208", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Timing attack: non-constant-time string comparison of HMAC or security token",
   ("The application compares an HMAC result or security token using regular string == or "
    "String.Equals() comparison. C#'s string comparison short-circuits on the first differing "
    "character, leaking timing information via network measurements. An attacker making many "
    "requests can statistically determine valid HMAC bytes and forge authentication tokens."),
   CS_SRC,
   ["== providedToken", "String.Equals(", ".Equals(expectedMac"],
   ["CryptographicOperations.FixedTimeEquals("],
   ("Use CryptographicOperations.FixedTimeEquals() for all HMAC and security-sensitive comparisons.\n\n"
    "UNSAFE:\n"
    "  if (computedHmac == providedHmac) { /* timing leak */ }\n\n"
    "SAFE (.NET 5+):\n"
    "  using System.Security.Cryptography;\n"
    "  if (CryptographicOperations.FixedTimeEquals(\n"
    "      computedHmac, providedHmac)) { /* constant-time */ }\n\n"
    "For older .NET: use a custom fixed-time compare with XOR across all bytes. "
    "See OWASP Cryptographic Storage Cheat Sheet.")
)

wr("csharp", "csharp_el_roslyn", RE["el_inj"],
   "Code Injection", "CWE-94", "A03:2021-Injection",
   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Confirmed",
   "Code Injection via Microsoft.CodeAnalysis.CSharp.Scripting (Roslyn) evaluating user input",
   ("User-controlled input is passed to CSharpScript.EvaluateAsync() or CSharpScript.RunAsync() "
    "from the Roslyn scripting API. This compiles and executes arbitrary C# code in the application "
    "process. An attacker can inject C# code to execute OS commands, access the filesystem, "
    "read environment variables, or exfiltrate data from within the application context."),
   CS_SRC,
   ["CSharpScript.EvaluateAsync(", "CSharpScript.RunAsync(", "Script.Create("],
   ["ScriptOptions.WithReferences(", "ScriptOptions.WithImports("],
   ("Never evaluate user-controlled input with Roslyn scripting. Use a safe expression evaluator instead.\n\n"
    "UNSAFE:\n"
    "  var result = await CSharpScript.EvaluateAsync(Request.Query[\"expression\"]);\n\n"
    "SAFE:\n"
    "  // Use a math-only expression parser (e.g., NCalc) for formula evaluation\n"
    "  // Never use Roslyn/CSharpScript with user input\n"
    "  var expr = new NCalc.Expression(sanitizedInput);\n"
    "  var result = expr.Evaluate();\n\n"
    "If dynamic code is required, sandbox it in a separate AppDomain with restricted permissions. "
    "See OWASP Injection Prevention Cheat Sheet.")
)

wr("csharp", "csharp_http_response_split", RE["resp_split"],
   "XSS", "CWE-113", "A03:2021-Injection",
   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "High", "Confirmed",
   "HTTP Response Splitting via unvalidated user input in Response.Headers.Add()",
   ("User-controlled input is written directly to an HTTP response header via "
    "Response.Headers.Add() or Response.Headers[key] without stripping CR/LF characters. "
    "An attacker can inject \\r\\n to split the HTTP response, injecting malicious headers or "
    "a second response body, enabling XSS, cache poisoning, or session fixation."),
   CS_SRC,
   ["Response.Headers.Add(", "Response.Headers[", "Response.AppendHeader("],
   ["Regex.Replace(", "Uri.EscapeDataString("],
   ("Strip or reject CR and LF characters from any user-controlled data before setting HTTP headers.\n\n"
    "UNSAFE:\n"
    "  Response.Headers.Add(\"X-User\", Request.Query[\"name\"]);\n\n"
    "SAFE:\n"
    "  var name = Regex.Replace(Request.Query[\"name\"], @\"[\\r\\n]\", \"\");\n"
    "  Response.Headers.Add(\"X-User\", name);\n\n"
    "In ASP.NET Core 5+, Response.Headers.Add() rejects header values with CR/LF by default. "
    "Upgrade and do not use workarounds that bypass this protection.")
)

wr("csharp", "csharp_sqli_fromsqlraw", RE["el_inj"],
   "SQLi", "CWE-89", "A03:2021-Injection",
   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Confirmed",
   "SQL Injection via Entity Framework FromSqlRaw() with concatenated user input",
   ("User-controlled data is concatenated into a raw SQL string passed to Entity Framework's "
    "FromSqlRaw(), ExecuteSqlRaw(), or FromSql() methods. Unlike FromSqlInterpolated(), "
    "FromSqlRaw() does NOT parameterize the interpolated values. An attacker can inject arbitrary "
    "SQL to read unauthorized data, modify records, or execute database-level commands."),
   CS_SRC,
   ["FromSqlRaw(", "ExecuteSqlRaw(", "Database.ExecuteSqlRaw("],
   ["FromSqlInterpolated(", "ExecuteSqlInterpolated("],
   ("Use FromSqlInterpolated() which safely parameterizes values, or use LINQ query syntax.\n\n"
    "UNSAFE:\n"
    "  var users = ctx.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\");\n\n"
    "SAFE (interpolated — automatically parameterized):\n"
    "  var users = ctx.Users.FromSqlInterpolated($\"SELECT * FROM Users WHERE Name = {name}\");\n\n"
    "FromSqlInterpolated wraps FormattableString — the {name} becomes a parameter, not a literal. "
    "See EF Core documentation and OWASP SQL Injection Prevention Cheat Sheet.")
)

# ════════════════════════════════════════════════════════════════════════════
# JavaScript — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("javascript", "js_zip_slip", RE["zip_slip"],
   "Path Traversal", "CWE-22", "A01:2021-Broken Access Control",
   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "Zip Slip path traversal via adm-zip, unzipper, or yauzl without entry path validation",
   ("The Node.js application extracts ZIP archive entries without validating that each entry's "
    "fileName remains within the intended extraction directory. An attacker who controls the "
    "uploaded ZIP can include entries with ../ path traversal sequences to write files outside the "
    "target directory, potentially placing a .env, reverse shell, or server-side script anywhere."),
   JS_SRC,
   ["entry.fileName", ".extractAllTo(", ".pipe(", "createWriteStream("],
   ["path.resolve(", "path.normalize(", "startsWith(outputPath"],
   ("Validate each archive entry's resolved path against the extraction root before writing.\n\n"
    "UNSAFE:\n"
    "  zip.extractAllTo(outputDir);  /* no path validation */\n\n"
    "SAFE:\n"
    "  zip.getEntries().forEach(entry => {\n"
    "    const dest = path.resolve(outputDir, entry.entryName);\n"
    "    if (!dest.startsWith(path.resolve(outputDir) + path.sep)) {\n"
    "      throw new Error('Zip Slip detected: ' + entry.entryName);\n"
    "    }\n"
    "    zip.extractEntryTo(entry, outputDir);\n"
    "  });\n\n"
    "See Snyk Zip Slip Vulnerability research and OWASP File Upload Cheat Sheet.")
)

wr("javascript", "js_timing_attack", RE["timing"],
   "Weak Crypto", "CWE-208", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Timing attack via === or == comparison of HMAC or secret token instead of timingSafeEqual",
   ("Node.js === operator for Buffer or string comparison short-circuits on the first differing "
    "byte, leaking comparison time via network latency measurements. An attacker making repeated "
    "requests with varying tokens can statistically determine the correct HMAC byte-by-byte, "
    "forging authentication tokens or API signatures over thousands of requests."),
   JS_SRC,
   ["=== token", "== expectedMac", ".toString() ==="],
   ["crypto.timingSafeEqual(", "timingSafeCompare("],
   ("Use crypto.timingSafeEqual() from Node's built-in crypto module for all HMAC comparisons.\n\n"
    "UNSAFE:\n"
    "  if (providedToken === expectedToken) { /* timing leak */ }\n"
    "  if (computedMac === requestMac) { /* timing leak */ }\n\n"
    "SAFE:\n"
    "  const crypto = require('crypto');\n"
    "  const safe = crypto.timingSafeEqual(\n"
    "    Buffer.from(providedToken),\n"
    "    Buffer.from(expectedToken)\n"
    "  );\n\n"
    "Both Buffers must be the same length. See Node.js crypto docs and OWASP Cryptographic Storage Cheat Sheet.")
)

wr("javascript", "js_graphql_injection", RE["graphql"],
   "Code Injection", "CWE-943", "A03:2021-Injection",
   8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "GraphQL Injection via user-controlled string concatenated into GraphQL query body",
   ("User-controlled input is concatenated directly into a GraphQL query or mutation string before "
    "sending it to a GraphQL endpoint. An attacker can close the current field, inject additional "
    "fields or fragments, or escape to query/mutation level to access unauthorized types, bypass "
    "authorization directives, or exfiltrate schema information via introspection."),
   JS_SRC,
   ["gql`", "graphql(", "`query {", "`mutation {"],
   ["variables:", "graphql(query, null, null, variables"],
   ("Always use GraphQL variables for all user-supplied values — never concatenate user input into query strings.\n\n"
    "UNSAFE:\n"
    "  const query = `{ user(id: \"${userId}\") { name email } }`;\n"
    "  client.query({ query: gql`${query}` });\n\n"
    "SAFE:\n"
    "  const GET_USER = gql`query GetUser($id: ID!) { user(id: $id) { name email } }`;\n"
    "  client.query({ query: GET_USER, variables: { id: userId } });\n\n"
    "Variables are serialized separately and never interpolated into the query string. "
    "See OWASP GraphQL Cheat Sheet and Apollo Client documentation.")
)

wr("javascript", "js_csv_injection", RE["csv_inj"],
   "Code Injection", "CWE-1236", "A03:2021-Injection",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High", "Tentative",
   "CSV Formula Injection: user-controlled values starting with =,+,@,- create executable formulas",
   ("User-supplied data containing leading = + @ - characters is written to a CSV file without "
    "sanitization. When a victim opens the file in Microsoft Excel, Google Sheets, or LibreOffice "
    "Calc, the cell is interpreted as a formula. An attacker can embed =HYPERLINK() to exfiltrate "
    "data via DNS, =SYSTEM() macros to execute commands, or dynamic array formulas to steal data."),
   JS_SRC,
   ["csvStringify(", "json2csv(", ".csv(", "createObjectCsvWriter("],
   ["sanitizeCsvValue("],
   ("Sanitize values that start with formula characters before writing to CSV output.\n\n"
    "UNSAFE:\n"
    "  const row = [userInput];  /* may start with =, +, @, - */\n"
    "  csvWriter.writeRecords([row]);\n\n"
    "SAFE:\n"
    "  function sanitizeCsv(value) {\n"
    "    if (/^[=+@\\-]/.test(String(value))) return \"'\" + value;\n"
    "    return value;\n"
    "  }\n"
    "  const row = [sanitizeCsv(userInput)];\n\n"
    "Prefix dangerous values with a single quote to force text interpretation. "
    "See OWASP CSV Injection defense guide.")
)

wr("javascript", "js_http_response_split", RE["resp_split"],
   "XSS", "CWE-113", "A03:2021-Injection",
   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "High", "Confirmed",
   "HTTP Response Splitting via unvalidated user input in Express res.setHeader() or res.set()",
   ("User-controlled data is written to an HTTP response header via res.setHeader() or res.set() "
    "without stripping carriage-return and line-feed characters. An attacker who can inject \\r\\n "
    "into a header value can split the response, inject arbitrary headers (Set-Cookie, Location), "
    "or create a second response body — enabling XSS, session fixation, or cache poisoning."),
   JS_SRC,
   ["res.setHeader(", "res.set(", "res.header("],
   ["encodeURIComponent(", "sanitizeHeader("],
   ("Remove or encode CR/LF characters from any user-controlled value before setting response headers.\n\n"
    "UNSAFE:\n"
    "  res.setHeader('X-User-Name', req.query.name);  /* may contain \\r\\n */\n\n"
    "SAFE:\n"
    "  const safeName = req.query.name.replace(/[\\r\\n]/g, '');\n"
    "  res.setHeader('X-User-Name', safeName);\n\n"
    "Avoid reflecting user input in response headers. Modern Node.js throws on CR/LF in headers but "
    "older versions do not. See OWASP HTTP Response Splitting defense guide.")
)

# ════════════════════════════════════════════════════════════════════════════
# Python — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("python", "python_zip_slip", RE["zip_slip"],
   "Path Traversal", "CWE-22", "A01:2021-Broken Access Control",
   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "Zip Slip path traversal via zipfile.extractall() without validating archive entry names",
   ("The application calls zipfile.ZipFile.extractall() or zipfile.ZipFile.extract() with a "
    "user-supplied or attacker-controlled ZIP archive without checking entry names for path "
    "traversal sequences. An attacker can craft a ZIP with entries named ../../../etc/cron.d/evil, "
    "causing files to be written outside the target directory."),
   PY_SRC,
   ["zipfile.ZipFile(", ".extractall(", ".extract("],
   ["os.path.abspath(", "zipfile.Path("],
   ("Validate every archive member's path before extraction using os.path.abspath().\n\n"
    "UNSAFE:\n"
    "  with zipfile.ZipFile(user_zip) as zf:\n"
    "      zf.extractall('/var/uploads/')  /* no path validation */\n\n"
    "SAFE:\n"
    "  import os, zipfile\n"
    "  target = os.path.abspath('/var/uploads/')\n"
    "  with zipfile.ZipFile(user_zip) as zf:\n"
    "      for member in zf.namelist():\n"
    "          dest = os.path.abspath(os.path.join(target, member))\n"
    "          if not dest.startswith(target + os.sep):\n"
    "              raise Exception('Zip Slip detected')\n"
    "          zf.extract(member, target)\n\n"
    "Python 3.12+ adds ZipFile.extractall() path validation. Upgrade or validate manually.")
)

wr("python", "python_timing_attack", RE["timing"],
   "Weak Crypto", "CWE-208", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Timing attack: non-constant-time == comparison of HMAC digest or security token",
   ("The application compares an HMAC digest or security token using Python's == operator, which "
    "short-circuits on the first differing byte. Repeated HTTP requests with varying tokens allow "
    "an attacker to statistically measure response times and determine valid HMAC values one byte "
    "at a time, forging authentication tokens or webhook signatures without knowing the secret key."),
   PY_SRC,
   ["== hmac", "== expected_token", "digest() ==", "hexdigest() =="],
   ["hmac.compare_digest(", "secrets.compare_digest("],
   ("Use hmac.compare_digest() for all HMAC and security-token comparisons.\n\n"
    "UNSAFE:\n"
    "  if provided_mac == hmac.new(key, msg, sha256).hexdigest():\n"
    "      pass  # timing leak\n\n"
    "SAFE:\n"
    "  import hmac\n"
    "  expected = hmac.new(key, msg, 'sha256').hexdigest()\n"
    "  if hmac.compare_digest(provided_mac, expected):\n"
    "      pass  # constant-time\n\n"
    "hmac.compare_digest() is always constant-time regardless of byte differences. "
    "See Python hmac docs and OWASP Cryptographic Storage Cheat Sheet.")
)

wr("python", "python_graphql_injection", RE["graphql"],
   "Code Injection", "CWE-943", "A03:2021-Injection",
   8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "GraphQL Injection via user-controlled string concatenated into GraphQL query string",
   ("User-controlled input is directly concatenated into a GraphQL query string passed to a "
    "GraphQL client or graphql.graphql() executor. An attacker can inject additional GraphQL "
    "fields, fragments, or directives to access unauthorized types, bypass field-level authorization, "
    "enumerate the schema via introspection, or trigger denial of service via deeply nested queries."),
   PY_SRC,
   ["graphql(", "client.execute(", "f\"query {", "f\"{ {"],
   ["variables=", "graphql_sync(schema, query, variable_values="],
   ("Use GraphQL variables for all user-supplied values — never string-concatenate user data into queries.\n\n"
    "UNSAFE:\n"
    "  query = f'{{ user(id: \"{user_id}\") {{ name email }} }}'\n"
    "  result = graphql_sync(schema, query)\n\n"
    "SAFE:\n"
    "  query = '{ user(id: $id) { name email } }'\n"
    "  result = graphql_sync(schema, query, variable_values={'id': user_id})\n\n"
    "Variables are parsed and typed separately from the query document. "
    "See OWASP GraphQL Cheat Sheet and Graphene Python documentation.")
)

wr("python", "python_csv_injection", RE["csv_inj"],
   "Code Injection", "CWE-1236", "A03:2021-Injection",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High", "Tentative",
   "CSV Formula Injection: user data with =,+,@,- prefix written to CSV without sanitization",
   ("User-supplied data containing leading formula characters (=, +, @, -, |) is written to a "
    "CSV file via csv.writer without sanitization. When the victim opens the exported CSV in "
    "Microsoft Excel or Google Sheets, the cell is executed as a formula. Attackers can embed "
    "=HYPERLINK() calls to exfiltrate data to external servers or =WEBSERVICE() to make HTTP requests."),
   PY_SRC,
   ["csv.writer(", "csvwriter.writerow(", "to_csv("],
   ["sanitize_csv("],
   ("Sanitize all values before writing to CSV by escaping leading formula characters.\n\n"
    "UNSAFE:\n"
    "  writer.writerow([user_name, user_email])\n\n"
    "SAFE:\n"
    "  def sanitize_csv(val):\n"
    "      val = str(val)\n"
    "      if val and val[0] in ('=', '+', '-', '@', '|', '%'):\n"
    "          val = \"'\" + val  # prepend quote to force text\n"
    "      return val\n"
    "  writer.writerow([sanitize_csv(user_name), sanitize_csv(user_email)])\n\n"
    "See OWASP CSV Injection defense and MITRE CWE-1236 for complete guidance.")
)

wr("python", "python_rsa_weak_padding", RE["timing"],
   "Weak Crypto", "CWE-327", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Confirmed",
   "Weak Crypto via RSA PKCS#1 v1.5 padding — vulnerable to Bleichenbacher oracle attack",
   ("The application uses RSA encryption with PKCS#1 v1.5 padding via cryptography.hazmat "
    "or pycryptodome. This padding scheme is vulnerable to the Bleichenbacher chosen-ciphertext "
    "attack (CVE-1998-0231), allowing an attacker who can submit arbitrary ciphertexts to the "
    "application to decrypt any RSA-encrypted message without the private key."),
   [],
   ["padding.PKCS1v15()", "PKCS1_v1_5.new(", "rsa.decrypt(", "rsa.encrypt("],
   ["padding.OAEP(", "SHA256("],
   ("Replace PKCS#1 v1.5 padding with OAEP (Optimal Asymmetric Encryption Padding) for encryption.\n\n"
    "UNSAFE:\n"
    "  from cryptography.hazmat.primitives.asymmetric import padding\n"
    "  ciphertext = pub_key.encrypt(message, padding.PKCS1v15())\n\n"
    "SAFE:\n"
    "  from cryptography.hazmat.primitives.asymmetric import padding\n"
    "  from cryptography.hazmat.primitives import hashes\n"
    "  ciphertext = pub_key.encrypt(\n"
    "      message,\n"
    "      padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)\n"
    "  )\n\n"
    "See OWASP Cryptographic Storage Cheat Sheet and RFC 8017 for RSA-OAEP guidance.")
)

# ════════════════════════════════════════════════════════════════════════════
# Java — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("java", "java_zip_slip", RE["zip_slip"],
   "Path Traversal", "CWE-22", "A01:2021-Broken Access Control",
   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "Zip Slip path traversal via ZipInputStream entry.getName() without path validation",
   ("The application extracts a ZIP archive using ZipInputStream without validating each entry's "
    "getName() path against the intended destination directory. An attacker-controlled ZIP file "
    "can contain entries with ../ traversal sequences that escape the target directory, writing "
    "arbitrary files to the server filesystem, including web-accessible directories."),
   JAVA_SRC,
   ["zipEntry.getName(", "new ZipInputStream(", "getNextEntry("],
   ["getCanonicalPath(", ".startsWith(destDir"],
   ("Validate each entry's canonical path against the target directory before extracting.\n\n"
    "UNSAFE:\n"
    "  ZipEntry entry = zis.getNextEntry();\n"
    "  new FileOutputStream(destDir + entry.getName());  /* no path check */\n\n"
    "SAFE:\n"
    "  ZipEntry entry = zis.getNextEntry();\n"
    "  File destFile = new File(destDir, entry.getName());\n"
    "  if (!destFile.getCanonicalPath().startsWith(new File(destDir).getCanonicalPath()))\n"
    "      throw new SecurityException(\"Zip Slip detected: \" + entry.getName());\n"
    "  new FileOutputStream(destFile);\n\n"
    "See Snyk Zip Slip research and OWASP File Upload Cheat Sheet for Java examples.")
)

wr("java", "java_timing_attack", RE["timing"],
   "Weak Crypto", "CWE-208", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Timing attack: non-constant-time comparison with String.equals() or Arrays.equals() for HMAC",
   ("The application uses String.equals() or Arrays.equals() to compare HMAC digests, API tokens, "
    "or password reset tokens. Both methods terminate early on the first mismatch, leaking timing "
    "information proportional to the number of matching bytes. Attackers can exploit this to forge "
    "tokens through remote timing analysis over large numbers of HTTP requests."),
   JAVA_SRC,
   ["Arrays.equals(mac", ".equals(expectedToken", "String.equals(digest"],
   ["MessageDigest.isEqual(", "HmacUtils.hmacSha256Hex("],
   ("Use MessageDigest.isEqual() for constant-time comparison of all cryptographic byte arrays.\n\n"
    "UNSAFE:\n"
    "  if (Arrays.equals(computedMac, providedMac)) { /* timing leak */ }\n"
    "  if (token.equals(expectedToken)) { /* timing leak */ }\n\n"
    "SAFE:\n"
    "  import java.security.MessageDigest;\n"
    "  if (MessageDigest.isEqual(computedMac, providedMac)) { /* constant-time */ }\n\n"
    "MessageDigest.isEqual() was introduced in Java 6 and is constant-time. "
    "See OWASP Cryptographic Storage Cheat Sheet.")
)

wr("java", "java_el_injection", RE["el_inj"],
   "Code Injection", "CWE-94", "A03:2021-Injection",
   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical", "Confirmed",
   "Code Injection via Spring EL (SpEL) expression evaluation with user-controlled input",
   ("User-supplied input is passed to Spring Expression Language evaluation via "
    "ExpressionParser.parseExpression() or @Value annotation with external data. SpEL can access "
    "any Java class through reflection. An attacker can inject a SpEL expression like "
    "T(java.lang.Runtime).getRuntime().exec('id') to execute arbitrary OS commands."),
   JAVA_SRC,
   ["parser.parseExpression(", "new SpelExpressionParser()", "StandardEvaluationContext"],
   ["SimpleEvaluationContext", "setPropertyAccessors("],
   ("Use SimpleEvaluationContext with a restricted property accessor instead of StandardEvaluationContext.\n\n"
    "UNSAFE:\n"
    "  ExpressionParser parser = new SpelExpressionParser();\n"
    "  Expression expr = parser.parseExpression(userInput);\n"
    "  Object result = expr.getValue();\n\n"
    "SAFE:\n"
    "  SimpleEvaluationContext ctx = SimpleEvaluationContext\n"
    "      .forReadOnlyDataBinding().build();\n"
    "  Expression expr = parser.parseExpression(\"#this.name\");\n"
    "  // userInput is passed as data, not as expression\n\n"
    "Never evaluate user-controlled strings as SpEL expressions. See CVE-2018-1270 (Spring Messaging RCE).")
)

wr("java", "java_graphql_injection", RE["graphql"],
   "Code Injection", "CWE-943", "A03:2021-Injection",
   8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "GraphQL Injection via user-controlled string concatenated into GraphQL query document",
   ("User-controlled input is concatenated into a GraphQL query document string before passing "
    "it to the GraphQL Java execution engine. An attacker can escape the current field context "
    "and inject additional fields, aliases, or fragments to access unauthorized data types, "
    "bypass field-level authorization decorators, or trigger expensive nested queries."),
   JAVA_SRC,
   ["ExecutionInput.newExecutionInput(", "GraphQL.execute(", "buildQuery("],
   ["variables(", "ExecutionInput.newExecutionInput().variables("],
   ("Use GraphQL variables for all user-supplied values — never concatenate into query strings.\n\n"
    "UNSAFE:\n"
    "  String query = \"{ user(id: \\\"\" + userId + \"\\\") { name } }\";\n"
    "  ExecutionInput input = ExecutionInput.newExecutionInput(query).build();\n\n"
    "SAFE:\n"
    "  String query = \"query GetUser($id: ID!) { user(id: $id) { name } }\";\n"
    "  ExecutionInput input = ExecutionInput.newExecutionInput(query)\n"
    "      .variables(Map.of(\"id\", userId)).build();\n\n"
    "See OWASP GraphQL Cheat Sheet and graphql-java documentation on variables.")
)

wr("java", "java_csv_injection", RE["csv_inj"],
   "Code Injection", "CWE-1236", "A03:2021-Injection",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High", "Tentative",
   "CSV Formula Injection: user data with formula prefix written to CSV without sanitization",
   ("User-supplied data starting with = + @ - | characters is written to CSV output via "
    "Apache Commons CSV, OpenCSV, or similar without formula injection protection. When the "
    "exported file is opened in Excel or Google Sheets, the cell is interpreted as a formula, "
    "enabling exfiltration via =WEBSERVICE() or DDE-based macro execution."),
   JAVA_SRC,
   ["csvPrinter.printRecord(", "csvWriter.writeNext(", "new CSVPrinter("],
   ["sanitizeCsvValue("],
   ("Sanitize all user values before writing to CSV output by escaping formula trigger characters.\n\n"
    "UNSAFE:\n"
    "  csvPrinter.printRecord(userName, userEmail);\n\n"
    "SAFE:\n"
    "  static String sanitizeCsv(String val) {\n"
    "      if (val != null && val.matches(\"^[=+@\\\\-|%].*\"))\n"
    "          return \"'\" + val;\n"
    "      return val;\n"
    "  }\n"
    "  csvPrinter.printRecord(sanitizeCsv(userName), sanitizeCsv(userEmail));\n\n"
    "See OWASP CSV Injection guide and MITRE CWE-1236 for complete defense guidance.")
)

# ════════════════════════════════════════════════════════════════════════════
# PHP — 5 rules
# ════════════════════════════════════════════════════════════════════════════

wr("php", "php_zip_slip", RE["zip_slip"],
   "Path Traversal", "CWE-22", "A01:2021-Broken Access Control",
   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "High", "Confirmed",
   "Zip Slip path traversal via PHP ZipArchive::extractTo() without validating entry names",
   ("The PHP application uses ZipArchive::extractTo() with an attacker-controlled archive without "
    "iterating and validating each entry's name for path traversal sequences. The PHP ZipArchive "
    "extension does not prevent ../ traversal in entry names by default. An attacker can write "
    "arbitrary files anywhere the web process has write permissions."),
   PHP_SRC,
   ["$zip->extractTo(", "ZipArchive::extractTo("],
   ["basename(", "realpath(", "ZipArchive::getNameIndex("],
   ("Iterate entries and validate each path before extraction with ZipArchive.\n\n"
    "UNSAFE:\n"
    "  $zip = new ZipArchive();\n"
    "  $zip->open($userZip);\n"
    "  $zip->extractTo('/var/uploads/');  /* no path validation */\n\n"
    "SAFE:\n"
    "  $target = realpath('/var/uploads/');\n"
    "  for ($i = 0; $i < $zip->numFiles; $i++) {\n"
    "      $name = $zip->getNameIndex($i);\n"
    "      $dest = realpath($target . '/' . $name);\n"
    "      if (strpos($dest, $target) !== 0) die('Zip Slip detected');\n"
    "  }\n"
    "  $zip->extractTo($target);\n\n"
    "See Snyk Zip Slip research and OWASP File Upload Cheat Sheet.")
)

wr("php", "php_timing_attack", RE["timing"],
   "Weak Crypto", "CWE-208", "A02:2021-Cryptographic Failures",
   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium", "Tentative",
   "Timing attack via PHP == or === comparison of HMAC digests instead of hash_equals()",
   ("The PHP application compares HMAC digests, CSRF tokens, or password reset tokens using the "
    "== or === operator. PHP's string comparison short-circuits on the first differing character, "
    "leaking timing information. An attacker making repeated requests can statistically determine "
    "valid HMAC bytes byte-by-byte, forging webhook signatures or API authentication tokens."),
   PHP_SRC,
   ["== $expectedMac", "=== $token", "$digest == $"],
   ["hash_equals("],
   ("Use hash_equals() for all HMAC, token, and cryptographic digest comparisons.\n\n"
    "UNSAFE:\n"
    "  if ($computedMac == $providedMac) { /* timing leak */ }\n"
    "  if ($token === $_GET['token']) { /* timing leak */ }\n\n"
    "SAFE:\n"
    "  if (hash_equals($computedMac, $providedMac)) { /* constant-time */ }\n\n"
    "hash_equals() was introduced in PHP 5.6 and is always constant-time. "
    "See PHP docs for hash_equals() and OWASP Cryptographic Storage Cheat Sheet.")
)

wr("php", "php_csv_injection", RE["csv_inj"],
   "Code Injection", "CWE-1236", "A03:2021-Injection",
   7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "High", "Tentative",
   "CSV Formula Injection: user data with =,+,@,- prefix written via fputcsv() without sanitation",
   ("User-supplied data starting with formula trigger characters (=, +, @, -, |) is written to a "
    "CSV file using fputcsv() without sanitization. When downloaded and opened in Microsoft Excel, "
    "LibreOffice Calc, or Google Sheets, the cell is executed as a formula. Attackers can exfiltrate "
    "data to external servers via =HYPERLINK() or trigger DDE command execution."),
   PHP_SRC,
   ["fputcsv(", "fputs($file", "fwrite($fp"],
   ["sanitizeCsv("],
   ("Sanitize field values before CSV output to prevent formula injection.\n\n"
    "UNSAFE:\n"
    "  fputcsv($handle, [$userInput]);\n\n"
    "SAFE:\n"
    "  function sanitizeCsvField($val) {\n"
    "      $val = (string)$val;\n"
    "      if (strlen($val) > 0 && in_array($val[0], ['=','+','-','@','|','%'])) {\n"
    "          return \"'\" . $val;\n"
    "      }\n"
    "      return $val;\n"
    "  }\n"
    "  fputcsv($handle, [sanitizeCsvField($userInput)]);\n\n"
    "See OWASP CSV Injection defense and MITRE CWE-1236.")
)

wr("php", "php_crlf_header", RE["resp_split"],
   "XSS", "CWE-113", "A03:2021-Injection",
   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "High", "Confirmed",
   "HTTP Response Splitting via PHP header() with unvalidated user input containing CR/LF",
   ("User-supplied input is incorporated into an HTTP header emitted via PHP's header() function "
    "without removing carriage-return (\\r) and line-feed (\\n) characters. An attacker can inject "
    "\\r\\n to terminate the current header and insert arbitrary headers (Set-Cookie, Location) or "
    "inject a second response body, enabling XSS, session fixation, or cache poisoning."),
   PHP_SRC,
   ["header(", "header_remove("],
   ["str_replace(\"\\r\", \"\",", "preg_replace('/[\\r\\n]/'"],
   ("Strip CR and LF characters from user input before using it in HTTP headers.\n\n"
    "UNSAFE:\n"
    "  header('X-User: ' . $_GET['username']);\n\n"
    "SAFE:\n"
    "  $safe = preg_replace('/[\\r\\n]+/', '', $_GET['username']);\n"
    "  header('X-User: ' . $safe);\n\n"
    "PHP 7.2+ throws E_WARNING on CR/LF in header values, but older versions do not. "
    "Apply sanitization explicitly for backwards-compatible code. "
    "See OWASP HTTP Response Splitting defense guide.")
)

wr("php", "php_regex_user_pattern", RE["csv_inj"],
   "ReDoS", "CWE-1333", "A06:2021-Vulnerable and Outdated Components",
   5.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "High", "Tentative",
   "ReDoS via PHP preg_match() or preg_replace() with user-controlled regex pattern",
   ("User-supplied input is used directly as the regex pattern argument to preg_match(), "
    "preg_replace(), or preg_match_all() without validation. An attacker can provide a "
    "catastrophically backtracking regex (e.g., (a+)+ with a long input) that causes PHP's PCRE "
    "engine to run exponentially, hanging the web server process and causing denial of service."),
   PHP_SRC,
   ["preg_match(", "preg_replace(", "preg_match_all("],
   ["preg_match('/^[a-z]+$/'"],
   ("Never allow user input to control the regex pattern argument. Use a hardcoded pattern.\n\n"
    "UNSAFE:\n"
    "  preg_match($_GET['pattern'], $subject);  /* attacker controls pattern */\n\n"
    "SAFE:\n"
    "  // Hardcode the pattern; only user controls the subject string\n"
    "  $allowed_pattern = '/^[a-zA-Z0-9_]+$/';\n"
    "  preg_match($allowed_pattern, $_GET['subject']);\n\n"
    "If user-defined patterns are required, validate against a strict allowlist of safe patterns "
    "and apply PHP's pcre.backtrack_limit and pcre.recursion_limit settings. "
    "See OWASP ReDoS prevention guide.")
)

print("\nBatch 12: All 40 rules written! Equal coverage across all 8 languages.")
