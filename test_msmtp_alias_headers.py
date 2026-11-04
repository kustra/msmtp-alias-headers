# SPDX-License-Identifier: GPL-3.0-or-later
#
# Tests for msmtp-alias-headers.
# Copyright (C) 2026 László Kustra
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import importlib.machinery
import importlib.util
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent / "msmtp-alias-headers"
loader = importlib.machinery.SourceFileLoader("wrapper", str(SCRIPT))
spec = importlib.util.spec_from_loader("wrapper", loader)
wrapper = importlib.util.module_from_spec(spec)
loader.exec_module(wrapper)

DEFAULT = {"default": ["owner@example.com"]}
NEEDS_STRICT = unittest.skipUnless(wrapper.STRICT_PARSER, "this Python's getaddresses lacks the CVE-2023-27043 fix")


def rewrite(text, aliases=DEFAULT):
    return wrapper.rewrite(text.encode(), lambda: aliases).decode()


def chain(length):
    """`length` aliases, each pointing to the next, the last to a full address."""
    aliases = {f"a{i}": [f"a{i + 1}"] for i in range(length - 1)}
    aliases[f"a{length - 1}"] = ["end@example.com"]
    return aliases


@NEEDS_STRICT
class Rewrite(unittest.TestCase):
    def test_local_to_takes_the_default_alias_and_the_body_stays(self):
        message = "To: root\nSubject: To: root\n\nTo: root\nbody\n"
        self.assertEqual(rewrite(message), "To: owner@example.com\nSubject: To: root\n\nTo: root\nbody\n")

    def test_cc_and_bcc_any_case_are_rewritten_and_from_is_not(self):
        message = "From: root\nCC: lk\nbcc: root\n\nx\n"
        self.assertEqual(rewrite(message), "From: root\nCC: owner@example.com\nbcc: owner@example.com\n\nx\n")

    def test_whitespace_before_the_colon_of_a_field_name(self):
        self.assertEqual(rewrite("To : root\n\nx\n"), "To : owner@example.com\n\nx\n")

    def test_a_qualified_address_beside_a_local_one_is_kept(self):
        message = "To: Bob <bob@example.com>, root\n\nx\n"
        self.assertEqual(rewrite(message), "To: Bob <bob@example.com>, owner@example.com\n\nx\n")

    def test_a_display_name_follows_its_expanded_address(self):
        self.assertEqual(rewrite("To: System <root>\n\nx\n"), "To: System <owner@example.com>\n\nx\n")

    def test_a_quoted_colon_is_not_a_group(self):
        self.assertEqual(rewrite('To: "Ops: night" <root>\n\nx\n'), 'To: "Ops: night" <owner@example.com>\n\nx\n')

    def test_a_field_with_only_qualified_addresses_is_byte_identical(self):
        message = 'To:   "Doe, Jane"  <jane@example.com>\n\nx\n'
        self.assertEqual(rewrite(message), message)

    def test_a_non_utf8_byte_in_an_untouched_field_survives(self):
        message = b"To: J\xf6rg <j@example.com>\n\nx\n"
        self.assertEqual(wrapper.rewrite(message, lambda: DEFAULT), message)

    def test_folds_with_space_and_tab_are_unfolded_and_the_next_field_kept(self):
        message = "To: root,\n lk,\n\tadm\nSubject: s\n\nx\n"
        expected = "To: owner@example.com, owner@example.com, owner@example.com\nSubject: s\n\nx\n"
        self.assertEqual(rewrite(message), expected)

    def test_a_whitespace_only_line_continues_the_headers(self):
        self.assertEqual(rewrite("To: root\n \nSubject: s\n\nx\n"), "To: owner@example.com\nSubject: s\n\nx\n")

    def test_crlf_line_ends_folds_and_the_body_bytes_are_preserved(self):
        message = b"To: root,\r\n lk\r\nSubject: s\r\n\r\nline\r\n.\r\n\xff\xfe\r\n"
        expected = b"To: owner@example.com, owner@example.com\r\nSubject: s\r\n\r\nline\r\n.\r\n\xff\xfe\r\n"
        self.assertEqual(wrapper.rewrite(message, lambda: DEFAULT), expected)

    def test_a_crlf_fold_inside_a_quoted_display_name(self):
        message = b'To: "Night\r\n Ops" <root>\r\n\r\nx\r\n'
        self.assertEqual(wrapper.rewrite(message, lambda: DEFAULT), b"To: Night Ops <owner@example.com>\r\n\r\nx\r\n")

    def test_a_named_alias_wins_over_default_and_lists_expand(self):
        aliases = {"root": ["a@example.com", "b@example.com"], "default": ["owner@example.com"]}
        self.assertEqual(rewrite("To: root, lk\n\nx\n", aliases), "To: a@example.com, b@example.com, owner@example.com\n\nx\n")

    def test_a_local_target_expands_again(self):
        aliases = {"root": ["admin"], "admin": ["a@example.com"]}
        self.assertEqual(rewrite("To: root\n\nx\n", aliases), "To: a@example.com\n\nx\n")

    def test_seventeen_chained_aliases_expand_and_eighteen_raise(self):
        self.assertEqual(rewrite("To: a0\n\nx\n", chain(17)), "To: end@example.com\n\nx\n")
        with self.assertRaisesRegex(ValueError, "too many redirects"):
            rewrite("To: a0\n\nx\n", chain(18))

    def test_an_alias_loop_raises(self):
        with self.assertRaisesRegex(ValueError, "too many redirects"):
            rewrite("To: root\n\nx\n", {"root": ["nobody"], "nobody": ["root"]})

    def test_a_local_address_without_alias_or_default_stays(self):
        message = "To: root\n\nx\n"
        self.assertEqual(rewrite(message, {"lk": ["a@example.com"]}), message)

    def test_groups_are_left_alone(self):
        for message in ("To: undisclosed-recipients:;\n\nx\n", "To: admins: root, lk;\n\nx\n"):
            self.assertEqual(rewrite(message), message)

    def test_a_field_the_parser_rejects_is_left_alone(self):
        for message in ("To: root, alice@example.org <bob@example.org>\n\nx\n", "To: root,\n\nx\n"):
            self.assertEqual(rewrite(message), message)

    def test_the_aliases_are_not_read_without_a_local_address(self):
        def unreadable():
            raise AssertionError("aliases read")

        message = b"To: a@example.com\nCc: b@example.com\n\nx\n"
        self.assertEqual(wrapper.rewrite(message, unreadable), message)

    def test_headers_without_a_body_and_without_a_final_newline(self):
        self.assertEqual(rewrite("Subject: s\nTo: root"), "Subject: s\nTo: owner@example.com")


class UnpatchedParser(unittest.TestCase):
    def test_a_parser_without_the_cve_fix_is_refused(self):
        with mock.patch.object(wrapper, "STRICT_PARSER", False):
            with self.assertRaisesRegex(RuntimeError, "CVE-2023-27043"):
                wrapper.rewrite(b"To: root\n\nx\n", lambda: DEFAULT)


class Aliases(unittest.TestCase):
    def load(self, content):
        with tempfile.NamedTemporaryFile("wb", suffix=".aliases", delete=False) as file:
            file.write(content)
        self.addCleanup(os.unlink, file.name)
        return wrapper.load_aliases(file.name)

    def test_comments_blank_lines_spacing_and_non_utf8_comments(self):
        content = b"# J\xf6rg\n\n   \nroot :  a@example.com ,b@example.com  # two\ndefault: c@example.com\n"
        self.assertEqual(self.load(content), {"root": ["a@example.com", "b@example.com"], "default": ["c@example.com"]})

    def test_what_msmtp_rejects_raises(self):
        cases = {
            b"root a@example.com\n": "single ':'",
            b"root: a@example.com:25\n": "single ':'",
            b"root@example.com: a@example.com\n": "invalid alias",
            b": a@example.com\n": "invalid alias",
            b"root: a@example.com\nroot: b@example.com\n": "duplicate alias",
            b"root:\n": "empty address",
            b"root: a@example.com, , b@example.com\n": "empty address",
        }
        for content, message in cases.items():
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, message):
                self.load(content)

    def test_a_line_of_511_bytes_raises_and_of_510_does_not(self):
        prefix = b"root: a@example.com,"
        fill = lambda n: prefix + b"b" * (n - len(prefix) - len(b"@example.com\n")) + b"@example.com\n"
        self.assertEqual(len(self.load(fill(510))["root"]), 2)
        with self.assertRaisesRegex(ValueError, "longer than 511"):
            self.load(fill(511))

    def test_only_the_first_32_targets_count(self):
        targets = ",".join(f"{i}@e.x" for i in range(33)).encode()
        self.assertEqual(self.load(b"root: " + targets + b"\n")["root"][-1], "31@e.x")


class Main(unittest.TestCase):
    """Runs main() in a child Python, with a stub msmtp that records its arguments and input."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        self.aliases = self.dir / "aliases"
        self.aliases.write_text("default: owner@example.com\n")
        self.msmtp = self.dir / "msmtp"
        self.stub(status="exit 0")

    def stub(self, status):
        args, message = shlex.quote(str(self.dir / "args")), shlex.quote(str(self.dir / "message"))
        self.msmtp.write_text(
            f'#!/bin/sh\nprintf "%s\\n" "$@" > {args}\n'
            f'[ "$1" = --version ] || cat > {message}\n{status}\n'
        )
        self.msmtp.chmod(0o755)

    def run_main(self, args, message=b"To: root\n\nbody\n", msmtp=None, stdin=None):
        # The child's warnings are checked on stderr; they stay out of the machine's mail log.
        code = (
            "import importlib.machinery, importlib.util, sys, syslog; "
            "syslog.syslog = lambda *args: None; "
            f"loader = importlib.machinery.SourceFileLoader('w', {str(SCRIPT)!r}); "
            "w = importlib.util.module_from_spec(importlib.util.spec_from_loader('w', loader)); "
            "loader.exec_module(w); "
            f"sys.exit(w.main(sys.argv[1:], {str(self.aliases)!r}, {str(msmtp or self.msmtp)!r}))"
        )
        command = [sys.executable, "-I", "-c", code, *args]
        if stdin is not None:
            return subprocess.run(command, stdin=stdin, capture_output=True, timeout=10)
        return subprocess.run(command, input=message, capture_output=True, timeout=10)

    @NEEDS_STRICT
    def test_msmtp_gets_the_rewritten_message_and_the_arguments_and_its_status_is_returned(self):
        self.stub(status="exit 75")
        result = self.run_main(["-i", "root"])
        self.assertEqual(result.returncode, 75)
        self.assertEqual((self.dir / "args").read_text(), "-i\nroot\n")
        self.assertEqual((self.dir / "message").read_bytes(), b"To: owner@example.com\n\nbody\n")
        self.assertEqual(result.stderr, b"")

    def test_a_signal_ending_msmtp_gives_128_plus_its_number(self):
        self.stub(status="kill -TERM $$")
        self.assertEqual(self.run_main(["root"]).returncode, 128 + 15)

    def test_a_failing_rewrite_passes_the_message_unchanged_and_warns(self):
        self.aliases.unlink()
        result = self.run_main(["root"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.dir / "message").read_bytes(), b"To: root\n\nbody\n")
        self.assertIn(b"passing the message to msmtp unchanged", result.stderr)

    @NEEDS_STRICT
    def test_without_a_local_address_the_aliases_file_is_not_needed(self):
        self.aliases.unlink()
        result = self.run_main(["a@example.com"], message=b"To: a@example.com\n\nbody\n")
        self.assertEqual((result.returncode, result.stderr), (0, b""))

    def test_a_missing_msmtp_gives_ex_unavailable(self):
        result = self.run_main(["root"], msmtp=self.dir / "absent")
        self.assertEqual(result.returncode, 69)
        self.assertIn(b"cannot run", result.stderr)

    def test_an_option_that_sends_nothing_runs_msmtp_without_reading_input(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, write_end)
        try:
            result = self.run_main(["--version"], stdin=read_end)
        finally:
            os.close(read_end)
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.dir / "args").read_text(), "--version\n")


if __name__ == "__main__":
    unittest.main()
