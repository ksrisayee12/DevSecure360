from rule_writer import write_rule

C_SOURCES = [
    "argv", "getenv", "read", "recv", "recvfrom", "fread", "fgets",
    "scanf", "fscanf", "sscanf", "gets"
]

CPP_SOURCES = [
    "std::cin", "std::getline", "getenv", "read", "recv",
    "ifstream", "istream", "stringstream"
]

def gen_c_cpp_rules():
    # -------------------------------------------------------------
    # C CORE MEMORY SAFETY (12 rules)
    # -------------------------------------------------------------
    
    # C Buffer Overflow Variants
    write_rule(
        "c", "c_bof_strcpy", "Buffer Overflow", "Critical", "CWE-120", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Buffer Overflow via strcpy",
        "The application uses the unsafe strcpy() function without checking if the source string exceeds the destination buffer size.",
        C_SOURCES,
        ["strcpy("],
        [],
        "Replace strcpy() with a safer alternative like strncpy(), strlcpy(), or explicitly bounds-check the input size before copying."
    )

    write_rule(
        "c", "c_bof_strcat", "Buffer Overflow", "Critical", "CWE-120", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Buffer Overflow via strcat",
        "The application uses the unsafe strcat() function, which assumes the destination buffer is large enough to hold the concatenated string.",
        C_SOURCES,
        ["strcat("],
        [],
        "Use strncat() or strlcat() to limit the number of bytes appended to the destination buffer, ensuring you leave room for the null terminator."
    )

    write_rule(
        "c", "c_bof_sprintf", "Buffer Overflow", "Critical", "CWE-120", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Buffer Overflow via sprintf",
        "The sprintf() function is used to format strings into a fixed-size buffer without bounds checking, potentially overwriting adjacent memory.",
        C_SOURCES,
        ["sprintf("],
        [],
        "Always use snprintf() instead of sprintf() to specify the maximum size of the destination buffer and prevent overflows."
    )

    write_rule(
        "c", "c_bof_gets", "Buffer Overflow", "Critical", "CWE-242", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Use of Inherently Dangerous Function gets()",
        "The application uses gets(), which reads from stdin until a newline is encountered without any buffer bounds checking. This is inherently unsafe.",
        [],
        ["gets("],
        [],
        "Remove all usage of gets(). Use fgets() instead, specifying the size of the destination buffer to strictly limit the maximum number of characters read from standard input."
    )

    write_rule(
        "c", "c_bof_memcpy_size", "Buffer Overflow", "Critical", "CWE-119", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Buffer Overflow via memcpy with Unvalidated Size",
        "The application uses memcpy() where the size parameter is derived from untrusted input, potentially causing out-of-bounds memory reads or writes.",
        C_SOURCES,
        ["memcpy("],
        [],
        "Strictly validate the size parameter against the bounds of both the source and destination buffers before calling memcpy()."
    )

    write_rule(
        "c", "c_bof_scanf", "Buffer Overflow", "Critical", "CWE-120", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Buffer Overflow via scanf without Width Specifier",
        "The application uses scanf() with an unbounded string format specifier (e.g., '%s'), which can overflow the destination buffer.",
        C_SOURCES,
        ["scanf(\"%s\"", "fscanf(", "sscanf("],
        [],
        "Use width specifiers in scanf (e.g., '%64s') or prefer safe input functions like fgets() for string reading."
    )

    # C Format String Variants
    write_rule(
        "c", "c_fmt_printf", "Format String", "Critical", "CWE-134", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability in printf",
        "The application passes untrusted input directly as the format string argument to printf(). Attackers can use format specifiers (%n, %x) to read or write arbitrary memory.",
        C_SOURCES,
        ["printf("],
        [],
        "Never use unvalidated user input as a format string. Hardcode the format string and pass the input as arguments (e.g., printf(\"%s\", input))."
    )

    write_rule(
        "c", "c_fmt_fprintf", "Format String", "Critical", "CWE-134", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability in fprintf",
        "The application passes untrusted input directly as the format string argument to fprintf(), potentially allowing arbitrary memory corruption.",
        C_SOURCES,
        ["fprintf("],
        [],
        "Pass a static format string to fprintf() and supply the user input as subsequent format arguments to avoid unexpected format string expansions."
    )

    write_rule(
        "c", "c_fmt_syslog", "Format String", "High", "CWE-134", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability in syslog",
        "The application passes untrusted input directly as the format string argument to syslog(), which can lead to memory corruption or denial of service.",
        C_SOURCES,
        ["syslog("],
        [],
        "Always use a static format string with syslog(), such as syslog(priority, \"%s\", input), to ensure input is safely parsed."
    )

    # C Memory/Pointer Safety
    write_rule(
        "c", "c_null_ptr_deref", "Null Pointer Dereference", "High", "CWE-476", "A03:2021-Injection", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Null Pointer Dereference",
        "The application dereferences a pointer that may be NULL without explicitly verifying its validity, potentially leading to application crashes.",
        [],
        ["*", "->"],
        [],
        "Always check pointers against NULL before dereferencing them, especially when they are returned by allocation functions or system calls."
    )

    write_rule(
        "c", "c_race_condition_file", "Race Condition", "High", "CWE-367", "A04:2021-Insecure Design", 7.0, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Time-of-Check Time-of-Use (TOCTOU) Race Condition",
        "The application checks file properties using stat() or access() and then acts on the file using open(), introducing a TOCTOU race condition window.",
        [],
        ["stat(", "access("],
        [],
        "Avoid using stat() or access() for security checks before open(). Instead, use open() directly and handle the resulting error codes."
    )

    write_rule(
        "c", "c_integer_overflow_malloc", "Integer Overflow", "Critical", "CWE-190", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", "Tentative",
        "Integer Overflow in Memory Allocation",
        "The application performs multiplication (e.g., size * sizeof(type)) within a malloc() call without bounds checking. An integer overflow can result in a smaller-than-expected allocation and a subsequent buffer overflow.",
        C_SOURCES,
        ["malloc(", "calloc(", "realloc("],
        [],
        "Validate the maximum values of inputs before performing arithmetic operations for memory allocation sizes, or use calloc() for arrays."
    )

    # -------------------------------------------------------------
    # CPP CORE MEMORY SAFETY (14 rules)
    # -------------------------------------------------------------
    
    # CPP Buffer Overflow Variants
    write_rule(
        "cpp", "cpp_bof_cstring", "Buffer Overflow", "High", "CWE-120", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Buffer Overflow via Legacy C Strings in C++",
        "The C++ application uses legacy, unsafe C string functions (strcpy, strcat, sprintf) instead of safer C++ standard library string features.",
        CPP_SOURCES,
        ["strcpy(", "strcat(", "sprintf("],
        [],
        "Replace legacy C string manipulation functions with safe C++ alternatives like std::string or string views for improved memory safety."
    )

    write_rule(
        "cpp", "cpp_bof_vector_unchecked", "Buffer Overflow", "High", "CWE-125", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", "Tentative",
        "Out-of-Bounds Access via std::vector::operator[]",
        "The application accesses std::vector elements using the unchecked operator[] with untrusted indices, which may lead to out-of-bounds memory read/write.",
        CPP_SOURCES,
        ["operator[]", "["],
        [],
        "Use the std::vector::at() method instead, which bounds-checks the index and throws an std::out_of_range exception if it is invalid."
    )

    write_rule(
        "cpp", "cpp_bof_memcpy", "Buffer Overflow", "Critical", "CWE-119", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Buffer Overflow via memcpy in C++",
        "The C++ application uses memcpy() with user-controlled size parameters, bypassing C++ object models and potentially causing memory corruption.",
        CPP_SOURCES,
        ["memcpy("],
        [],
        "Validate size parameters before calling memcpy(), or preferably use std::copy() or std::string for data manipulation."
    )

    write_rule(
        "cpp", "cpp_bof_string_copy", "Buffer Overflow", "High", "CWE-120", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Buffer Overflow via std::string::copy",
        "The application uses std::string::copy() to write data into a raw character buffer without explicit validation that the destination buffer is large enough.",
        CPP_SOURCES,
        ["string.copy("],
        [],
        "Ensure the destination buffer length is rigorously checked against the requested copy length before invoking std::string::copy()."
    )

    # CPP Memory/Pointer Safety
    write_rule(
        "cpp", "cpp_uaf_raw_delete", "Use After Free", "Critical", "CWE-416", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Use-After-Free via Raw delete",
        "The application manually deletes a raw pointer and subsequently dereferences it. This can lead to arbitrary code execution or crashes.",
        [],
        ["delete"],
        [],
        "Avoid using raw pointers and manual memory management. Migrate to C++ smart pointers (std::unique_ptr, std::shared_ptr) to automate memory lifecycles."
    )

    write_rule(
        "cpp", "cpp_null_ptr_deref", "Null Pointer Dereference", "High", "CWE-476", "A03:2021-Injection", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Null Pointer Dereference in C++",
        "The application dereferences a pointer that may be nullptr without validation, which will cause an application crash (Denial of Service).",
        [],
        ["*", "->"],
        [],
        "Always test raw pointers against nullptr before dereferencing. Prefer using references or smart pointers that guarantee initialization."
    )

    write_rule(
        "cpp", "cpp_race_condition_shared", "Race Condition", "High", "CWE-362", "A04:2021-Insecure Design", 7.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H", "Tentative",
        "Race Condition on std::shared_ptr",
        "The application accesses or modifies a std::shared_ptr concurrently across multiple threads without synchronization, leading to race conditions on the control block.",
        [],
        ["shared_ptr"],
        [],
        "Use std::atomic<std::shared_ptr> or synchronize access with std::mutex when multiple threads concurrently read and write to the same shared_ptr."
    )

    write_rule(
        "cpp", "cpp_out_of_bounds_array", "Buffer Overflow", "High", "CWE-119", "A03:2021-Injection", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Tentative",
        "Out-of-Bounds Access on Raw Arrays",
        "The application indexes into a C-style array using unvalidated user input, which can result in out-of-bounds reads or writes.",
        CPP_SOURCES,
        ["["],
        [],
        "Replace raw C-style arrays with std::array or std::vector and use the bounds-checked .at() method for element access."
    )

    # CPP Integer Overflow Variants
    write_rule(
        "cpp", "cpp_int_overflow_new", "Integer Overflow", "Critical", "CWE-190", "A03:2021-Injection", 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", "Tentative",
        "Integer Overflow in Array Allocation",
        "The application uses an unchecked user-supplied integer to size an array allocation via 'new T[size]'. An overflow can lead to undersized allocation and heap corruption.",
        CPP_SOURCES,
        ["new "],
        [],
        "Validate bounds and constraints on allocation sizes before using the 'new' operator, or prefer std::vector which handles sizing safely."
    )

    write_rule(
        "cpp", "cpp_int_overflow_vector", "Integer Overflow", "High", "CWE-190", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "Tentative",
        "Integer Overflow in std::vector::resize",
        "The application calls std::vector::resize() using an unchecked integer derived from user input, potentially leading to excessive resource consumption (OOM) or integer wrap.",
        CPP_SOURCES,
        ["vector.resize("],
        [],
        "Validate the requested size against application-defined limits before calling resize() to prevent resource exhaustion."
    )

    write_rule(
        "cpp", "cpp_int_overflow_arithmetic", "Integer Overflow", "High", "CWE-190", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", "Tentative",
        "Integer Overflow in Allocation Arithmetic",
        "The application performs multiplication or addition on variables before passing them to memory allocation functions without verifying for arithmetic overflow.",
        CPP_SOURCES,
        ["*", "+"],
        [],
        "Implement safe math routines (e.g., checking for overflow explicitly) before relying on arithmetic results for buffer sizing."
    )

    # CPP Format String Variants
    write_rule(
        "cpp", "cpp_fmt_printf", "Format String", "Critical", "CWE-134", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability in C++ printf",
        "The C++ application uses the legacy printf() function and passes untrusted data directly as the format string argument.",
        CPP_SOURCES,
        ["printf("],
        [],
        "Avoid legacy C functions. Use std::cout, std::format (C++20), or the fmt library for safe, typed formatting."
    )

    write_rule(
        "cpp", "cpp_fmt_sprintf", "Format String", "Critical", "CWE-134", "A03:2021-Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Confirmed",
        "Format String Vulnerability in C++ sprintf",
        "The C++ application uses the legacy sprintf() function and passes untrusted data directly as the format string argument.",
        CPP_SOURCES,
        ["sprintf("],
        [],
        "Avoid legacy C functions. Use std::ostringstream, std::format (C++20), or the fmt library for safe formatting."
    )

    write_rule(
        "cpp", "cpp_fmt_boost_format", "Format String", "High", "CWE-134", "A03:2021-Injection", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H", "Tentative",
        "Format String Vulnerability in boost::format",
        "The application passes untrusted input directly to boost::format(), which can trigger exceptions or unexpected formatting logic.",
        CPP_SOURCES,
        ["boost::format("],
        [],
        "Use a hardcoded string literal for the format specifier and pass untrusted data securely via the formatting arguments (e.g., the '%' operator)."
    )

if __name__ == '__main__':
    gen_c_cpp_rules()
