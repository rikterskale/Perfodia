"""Tests for input sanitizer."""

from utils.sanitizer import sanitize_arg, sanitize_args, sanitize_hostname, is_safe_path


class TestSanitizeArg:
    def test_clean_arg_unchanged(self):
        assert sanitize_arg("-sV") == "-sV"
        assert sanitize_arg("192.168.1.1") == "192.168.1.1"
        assert sanitize_arg("--max-rate") == "--max-rate"

    def test_semicolon_removed(self):
        result = sanitize_arg("-sV; rm -rf /")
        assert ";" not in result

    def test_pipe_removed(self):
        result = sanitize_arg("test | cat /etc/passwd")
        assert "|" not in result

    def test_backtick_removed(self):
        result = sanitize_arg("`whoami`")
        assert "`" not in result

    def test_dollar_paren_removed(self):
        result = sanitize_arg("$(id)")
        assert "$(" not in result

    def test_null_byte_removed(self):
        result = sanitize_arg("test\x00injection")
        assert "\x00" not in result

    def test_newline_replaced(self):
        result = sanitize_arg("line1\nline2")
        assert "\n" not in result

    def test_empty_string(self):
        assert sanitize_arg("") == ""

    def test_normal_tool_args_preserved(self):
        assert sanitize_arg("user:password@192.168.1.1") == "user:password@192.168.1.1"
        assert (
            sanitize_arg("/usr/share/wordlists/rockyou.txt") == "/usr/share/wordlists/rockyou.txt"
        )
        assert sanitize_arg("-p") == "-p"


class TestSanitizeArgs:
    def test_list_sanitized(self):
        result = sanitize_args(["-sV", "192.168.1.1", "--max-rate", "500"])
        assert result == ["-sV", "192.168.1.1", "--max-rate", "500"]

    def test_dangerous_args_cleaned(self):
        result = sanitize_args(["-sV", "$(whoami)", "test;id"])
        assert all("$(" not in a and ";" not in a for a in result)

    def test_empty_args_dropped(self):
        result = sanitize_args(["", "valid", ""])
        assert result == ["valid"]


class TestSanitizeHostname:
    def test_valid_ip(self):
        assert sanitize_hostname("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert sanitize_hostname("server.lab.local") == "server.lab.local"

    def test_injection_stripped(self):
        result = sanitize_hostname("server.lab; id")
        assert ";" not in result

    def test_ipv6(self):
        assert sanitize_hostname("::1") == "::1"


class TestIsSafePath:
    def test_normal_path(self):
        assert is_safe_path("/usr/share/wordlists/rockyou.txt") is True

    def test_traversal_blocked(self):
        assert is_safe_path("../../etc/passwd") is False

    def test_empty(self):
        assert is_safe_path("") is False

    def test_shell_chars_blocked(self):
        assert is_safe_path("/tmp/file;rm -rf /") is False
