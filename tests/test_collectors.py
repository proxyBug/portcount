from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from portcount.cli import build_parser, main
from portcount.collectors import (
    _dedupe_notes,
    _safe_int,
    collect_docker_containers,
    collect_inventory,
    collect_listening_sockets,
    infer_systemd_unit,
    lookup_user,
    parse_docker_port_mappings,
    parse_netstat_line,
    parse_process_field,
    parse_ss_line,
    parse_unit_from_cgroup,
    split_host_port,
)
from portcount.formatters import format_report, render_json, render_markdown, render_table
from portcount.models import ContainerInfo, ContainerPortMapping, InventoryReport, ListeningSocket


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_minimal_report() -> InventoryReport:
    return InventoryReport(
        hostname="test-host",
        generated_at="2026-01-01T00:00:00+00:00",
        endpoints=[],
        containers=[],
        notes=[],
    )


def _make_report_with_endpoint() -> InventoryReport:
    return InventoryReport(
        hostname="test-host",
        generated_at="2026-01-01T00:00:00+00:00",
        endpoints=[
            ListeningSocket(
                protocol="tcp",
                state="LISTEN",
                bind_address="0.0.0.0",
                port=22,
                pid=123,
                process_name="sshd",
                user="root",
                systemd_unit="ssh.service",
            )
        ],
        containers=[],
        notes=[],
    )


# ---------------------------------------------------------------------------
# split_host_port
# ---------------------------------------------------------------------------


class SplitHostPortTests(unittest.TestCase):
    def test_ipv4(self) -> None:
        self.assertEqual(split_host_port("0.0.0.0:22"), ("0.0.0.0", 22))

    def test_ipv6(self) -> None:
        self.assertEqual(split_host_port("[::]:443"), ("::", 443))

    def test_ipv6_without_brackets(self) -> None:
        self.assertEqual(split_host_port(":::80"), ("::", 80))


# ---------------------------------------------------------------------------
# _safe_int
# ---------------------------------------------------------------------------


class SafeIntTests(unittest.TestCase):
    def test_valid_integer(self) -> None:
        self.assertEqual(_safe_int("42"), 42)

    def test_non_numeric_string(self) -> None:
        self.assertIsNone(_safe_int("abc"))

    def test_empty_string(self) -> None:
        self.assertIsNone(_safe_int(""))

    def test_none_value(self) -> None:
        self.assertIsNone(_safe_int(None))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# parse_process_field
# ---------------------------------------------------------------------------


class ParseProcessFieldTests(unittest.TestCase):
    def test_none_returns_none(self) -> None:
        self.assertEqual(parse_process_field(None), (None, None))

    def test_empty_string_returns_none(self) -> None:
        self.assertEqual(parse_process_field(""), (None, None))

    def test_single_process(self) -> None:
        pid, name = parse_process_field('users:(("nginx",pid=456,fd=6))')
        self.assertEqual(pid, 456)
        self.assertEqual(name, "nginx")

    def test_prefers_non_systemd_over_systemd(self) -> None:
        value = 'users:(("sshd",pid=123,fd=3),("systemd",pid=1,fd=118))'
        pid, name = parse_process_field(value)
        self.assertEqual(pid, 123)
        self.assertEqual(name, "sshd")

    def test_falls_back_to_first_when_all_system_processes(self) -> None:
        value = 'users:(("systemd",pid=1,fd=10),("init",pid=2,fd=5))'
        pid, name = parse_process_field(value)
        self.assertEqual(pid, 1)
        self.assertEqual(name, "systemd")


# ---------------------------------------------------------------------------
# parse_ss_line / parse_netstat_line / parse_unit_from_cgroup
# ---------------------------------------------------------------------------


class ParsingTests(unittest.TestCase):
    @patch("portcount.collectors.lookup_user", return_value="root")
    @patch("portcount.collectors.infer_systemd_unit", return_value="ssh.service")
    def test_parse_ss_line(self, _unit: object, _user: object) -> None:
        line = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3),("systemd",pid=1,fd=118))'
        parsed = parse_ss_line(line)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.protocol, "tcp")
        self.assertEqual(parsed.bind_address, "0.0.0.0")
        self.assertEqual(parsed.port, 22)
        self.assertEqual(parsed.pid, 123)
        self.assertEqual(parsed.process_name, "sshd")
        self.assertEqual(parsed.user, "root")
        self.assertEqual(parsed.systemd_unit, "ssh.service")

    def test_parse_docker_ports(self) -> None:
        ports = parse_docker_port_mappings("0.0.0.0:80->80/tcp, [::]:443->443/tcp, 9000/udp")
        self.assertEqual(len(ports), 3)
        self.assertEqual(ports[0].host_ip, "0.0.0.0")
        self.assertEqual(ports[0].host_port, 80)
        self.assertEqual(ports[0].container_port, 80)
        self.assertEqual(ports[1].host_ip, "::")
        self.assertEqual(ports[2].host_port, None)
        self.assertEqual(ports[2].container_port, 9000)
        self.assertEqual(ports[2].protocol, "udp")

    def test_parse_unit_from_cgroup(self) -> None:
        cgroup = "0::/system.slice/docker.service\n1:name=systemd:/system.slice/ssh.service\n"
        self.assertEqual(parse_unit_from_cgroup(cgroup), "docker.service")


class ParseNetstatLineTests(unittest.TestCase):
    @patch("portcount.collectors.lookup_user", return_value=None)
    @patch("portcount.collectors.infer_systemd_unit", return_value=None)
    def test_tcp_listen_line(self, _unit: object, _user: object) -> None:
        line = "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      456/sshd"
        parsed = parse_netstat_line(line)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.protocol, "tcp")
        self.assertEqual(parsed.port, 22)
        self.assertEqual(parsed.state, "LISTEN")
        self.assertEqual(parsed.pid, 456)
        self.assertEqual(parsed.process_name, "sshd")
        self.assertEqual(parsed.source, "netstat")

    @patch("portcount.collectors.lookup_user", return_value=None)
    @patch("portcount.collectors.infer_systemd_unit", return_value=None)
    def test_udp_line_has_unconn_state(self, _unit: object, _user: object) -> None:
        line = "udp        0      0 0.0.0.0:53              0.0.0.0:*                           789/named"
        parsed = parse_netstat_line(line)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.protocol, "udp")
        self.assertEqual(parsed.state, "UNCONN")
        self.assertEqual(parsed.pid, 789)
        self.assertEqual(parsed.process_name, "named")

    def test_proto_header_returns_none(self) -> None:
        self.assertIsNone(parse_netstat_line("Proto Recv-Q Send-Q Local Address Foreign Address State"))

    def test_active_connections_header_returns_none(self) -> None:
        self.assertIsNone(parse_netstat_line("Active Internet connections (only servers)"))

    def test_too_few_fields_returns_none(self) -> None:
        self.assertIsNone(parse_netstat_line("tcp 0 0"))


# ---------------------------------------------------------------------------
# lookup_user / infer_systemd_unit
# ---------------------------------------------------------------------------


class LookupUserTests(unittest.TestCase):
    def test_none_pid_returns_none(self) -> None:
        self.assertIsNone(lookup_user(None))

    @patch("portcount.collectors.Path")
    def test_missing_proc_entry_returns_none(self, mock_path: MagicMock) -> None:
        mock_path.return_value.stat.side_effect = FileNotFoundError
        self.assertIsNone(lookup_user(99999))

    @patch("portcount.collectors.Path")
    def test_permission_error_returns_none(self, mock_path: MagicMock) -> None:
        mock_path.return_value.stat.side_effect = PermissionError
        self.assertIsNone(lookup_user(1))

    @patch("portcount.collectors.pwd")
    @patch("portcount.collectors.Path")
    def test_resolves_uid_to_username(self, mock_path: MagicMock, mock_pwd: MagicMock) -> None:
        mock_path.return_value.stat.return_value.st_uid = 1000
        mock_pwd.getpwuid.return_value.pw_name = "alice"
        self.assertEqual(lookup_user(42), "alice")


class InferSystemdUnitTests(unittest.TestCase):
    def test_none_pid_returns_none(self) -> None:
        self.assertIsNone(infer_systemd_unit(None))

    @patch("portcount.collectors.Path")
    def test_missing_cgroup_file_returns_none(self, mock_path: MagicMock) -> None:
        mock_path.return_value.read_text.side_effect = FileNotFoundError
        self.assertIsNone(infer_systemd_unit(99999))

    @patch("portcount.collectors.Path")
    def test_extracts_service_unit(self, mock_path: MagicMock) -> None:
        mock_path.return_value.read_text.return_value = "0::/system.slice/nginx.service\n"
        self.assertEqual(infer_systemd_unit(42), "nginx.service")


# ---------------------------------------------------------------------------
# _dedupe_notes
# ---------------------------------------------------------------------------


class DedupNotesTests(unittest.TestCase):
    def test_empty_list(self) -> None:
        self.assertEqual(_dedupe_notes([]), [])

    def test_removes_duplicates_preserving_order(self) -> None:
        self.assertEqual(_dedupe_notes(["a", "b", "a"]), ["a", "b"])

    def test_filters_blank_strings(self) -> None:
        self.assertEqual(_dedupe_notes(["a", "", "  ", "b"]), ["a", "b"])

    def test_preserves_insertion_order(self) -> None:
        self.assertEqual(_dedupe_notes(["c", "a", "b"]), ["c", "a", "b"])


# ---------------------------------------------------------------------------
# collect_listening_sockets
# ---------------------------------------------------------------------------


class CollectListeningSocketsTests(unittest.TestCase):
    @patch("portcount.collectors.lookup_user", return_value=None)
    @patch("portcount.collectors.infer_systemd_unit", return_value=None)
    @patch("portcount.collectors._run_command")
    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/ss")
    def test_uses_ss_when_available(
        self, _which: MagicMock, mock_run: MagicMock, _unit: MagicMock, _user: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n',
            stderr="",
        )
        sockets, notes = collect_listening_sockets()
        self.assertEqual(len(sockets), 1)
        self.assertEqual(sockets[0].port, 22)
        self.assertEqual(notes, [])

    @patch("portcount.collectors.lookup_user", return_value=None)
    @patch("portcount.collectors.infer_systemd_unit", return_value=None)
    @patch("portcount.collectors._run_command")
    @patch("portcount.collectors.shutil.which")
    def test_falls_back_to_netstat_when_ss_absent(
        self, mock_which: MagicMock, mock_run: MagicMock, _unit: MagicMock, _user: MagicMock
    ) -> None:
        mock_which.side_effect = lambda cmd: "/usr/bin/netstat" if cmd == "netstat" else None
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1/nginx\n",
            stderr="",
        )
        sockets, notes = collect_listening_sockets()
        self.assertEqual(len(sockets), 1)
        self.assertEqual(sockets[0].port, 80)
        self.assertEqual(sockets[0].source, "netstat")

    @patch("portcount.collectors.shutil.which", return_value=None)
    def test_no_tools_returns_empty_with_note(self, _which: MagicMock) -> None:
        sockets, notes = collect_listening_sockets()
        self.assertEqual(sockets, [])
        self.assertIn("No supported socket inspection tool was available.", notes)

    @patch("portcount.collectors._run_command")
    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/ss")
    def test_ss_stderr_warning_included_in_notes(self, _which: MagicMock, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="permission denied")
        _, notes = collect_listening_sockets()
        self.assertTrue(any("ss reported" in note for note in notes))


# ---------------------------------------------------------------------------
# collect_docker_containers
# ---------------------------------------------------------------------------


class CollectDockerContainersTests(unittest.TestCase):
    @patch("portcount.collectors.shutil.which", return_value=None)
    def test_docker_not_installed(self, _which: MagicMock) -> None:
        containers, notes = collect_docker_containers()
        self.assertEqual(containers, [])
        self.assertIn("docker is not installed.", notes)

    @patch("portcount.collectors._run_command")
    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/docker")
    def test_docker_ps_failure_adds_note(self, _which: MagicMock, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Cannot connect to daemon")
        containers, notes = collect_docker_containers()
        self.assertEqual(containers, [])
        self.assertTrue(any("docker ps failed" in note for note in notes))

    @patch("portcount.collectors._run_command")
    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/docker")
    def test_docker_ps_parses_containers(self, _which: MagicMock, mock_run: MagicMock) -> None:
        row = json.dumps({"Names": "nginx", "Image": "nginx:1.27", "Status": "Up 2 hours", "Ports": "0.0.0.0:80->80/tcp"})
        mock_run.return_value = MagicMock(returncode=0, stdout=row + "\n", stderr="")
        containers, notes = collect_docker_containers()
        self.assertEqual(len(containers), 1)
        self.assertEqual(containers[0].name, "nginx")
        self.assertEqual(containers[0].image, "nginx:1.27")
        self.assertEqual(len(containers[0].ports), 1)
        self.assertEqual(containers[0].ports[0].host_port, 80)
        self.assertEqual(notes, [])


# ---------------------------------------------------------------------------
# collect_inventory
# ---------------------------------------------------------------------------


class CollectInventoryTests(unittest.TestCase):
    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/systemctl")
    @patch("portcount.collectors.collect_docker_containers")
    @patch("portcount.collectors.collect_listening_sockets")
    def test_skips_docker_when_disabled(
        self, mock_sockets: MagicMock, mock_docker: MagicMock, _which: MagicMock
    ) -> None:
        mock_sockets.return_value = ([], [])
        report = collect_inventory(include_docker=False)
        mock_docker.assert_not_called()
        self.assertEqual(report.containers, [])

    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/systemctl")
    @patch("portcount.collectors.collect_docker_containers")
    @patch("portcount.collectors.collect_listening_sockets")
    def test_merges_notes_from_both_collectors(
        self, mock_sockets: MagicMock, mock_docker: MagicMock, _which: MagicMock
    ) -> None:
        mock_sockets.return_value = ([], ["ss is missing"])
        mock_docker.return_value = ([], ["docker is not installed."])
        report = collect_inventory(include_docker=True, include_systemd=True)
        self.assertIn("ss is missing", report.notes)
        self.assertIn("docker is not installed.", report.notes)

    @patch("portcount.collectors.shutil.which", return_value="/usr/bin/systemctl")
    @patch("portcount.collectors.collect_docker_containers")
    @patch("portcount.collectors.collect_listening_sockets")
    def test_deduplicates_notes(
        self, mock_sockets: MagicMock, mock_docker: MagicMock, _which: MagicMock
    ) -> None:
        mock_sockets.return_value = ([], ["docker is not installed."])
        mock_docker.return_value = ([], ["docker is not installed."])
        report = collect_inventory(include_docker=True)
        self.assertEqual(report.notes.count("docker is not installed."), 1)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class FormatterTests(unittest.TestCase):
    def test_render_markdown(self) -> None:
        report = InventoryReport(
            hostname="example-host",
            generated_at="2026-03-12T11:55:00+00:00",
            endpoints=[
                ListeningSocket(
                    protocol="tcp",
                    state="LISTEN",
                    bind_address="0.0.0.0",
                    port=22,
                    pid=123,
                    process_name="sshd",
                    user="root",
                    systemd_unit="ssh.service",
                )
            ],
            containers=[
                ContainerInfo(
                    name="nginx",
                    image="nginx:1.27",
                    status="Up 2 hours",
                    ports_raw="0.0.0.0:8080->80/tcp",
                    ports=[
                        ContainerPortMapping(
                            host_ip="0.0.0.0",
                            host_port=8080,
                            container_port=80,
                            protocol="tcp",
                            raw="0.0.0.0:8080->80/tcp",
                        )
                    ],
                )
            ],
            notes=["docker is not installed."],
        )
        rendered = render_markdown(report)
        self.assertIn("# portcount inventory", rendered)
        self.assertIn("| tcp | LISTEN | 0.0.0.0 | 22 | sshd | 123 | root | ssh.service |", rendered)
        self.assertIn("nginx:1.27", rendered)
        self.assertIn("docker is not installed.", rendered)

    def test_render_markdown_empty_endpoints_message(self) -> None:
        rendered = render_markdown(_make_minimal_report())
        self.assertIn("No listening endpoints detected.", rendered)
        self.assertIn("No running containers detected.", rendered)


class RenderJsonTests(unittest.TestCase):
    def test_produces_valid_json(self) -> None:
        data = json.loads(render_json(_make_minimal_report()))
        self.assertEqual(data["hostname"], "test-host")
        self.assertIn("endpoints", data)
        self.assertIn("containers", data)
        self.assertIn("notes", data)

    def test_output_ends_with_newline(self) -> None:
        self.assertTrue(render_json(_make_minimal_report()).endswith("\n"))

    def test_endpoint_fields_serialized(self) -> None:
        data = json.loads(render_json(_make_report_with_endpoint()))
        self.assertEqual(len(data["endpoints"]), 1)
        self.assertEqual(data["endpoints"][0]["port"], 22)
        self.assertEqual(data["endpoints"][0]["process_name"], "sshd")


class RenderTableTests(unittest.TestCase):
    def test_contains_section_headers(self) -> None:
        output = render_table(_make_minimal_report())
        self.assertIn("LISTENING PORTS", output)
        self.assertIn("DOCKER CONTAINERS", output)

    def test_contains_column_headers(self) -> None:
        output = render_table(_make_report_with_endpoint())
        self.assertIn("PROTO", output)
        self.assertIn("PORT", output)
        self.assertIn("UNIT", output)

    def test_contains_endpoint_data(self) -> None:
        output = render_table(_make_report_with_endpoint())
        self.assertIn("sshd", output)
        self.assertIn("22", output)

    def test_empty_endpoints_message(self) -> None:
        self.assertIn("No listening endpoints detected.", render_table(_make_minimal_report()))

    def test_notes_section_present(self) -> None:
        report = InventoryReport(
            hostname="h",
            generated_at="2026-01-01T00:00:00+00:00",
            endpoints=[],
            containers=[],
            notes=["something happened"],
        )
        output = render_table(report)
        self.assertIn("NOTES", output)
        self.assertIn("something happened", output)


class FormatReportTests(unittest.TestCase):
    def test_json_dispatch(self) -> None:
        json.loads(format_report(_make_minimal_report(), "json"))  # must not raise

    def test_table_dispatch(self) -> None:
        self.assertIn("LISTENING PORTS", format_report(_make_minimal_report(), "table"))

    def test_markdown_dispatch(self) -> None:
        self.assertIn("# portcount inventory", format_report(_make_minimal_report(), "markdown"))

    def test_unknown_format_defaults_to_markdown(self) -> None:
        self.assertIn("# portcount inventory", format_report(_make_minimal_report(), "unknown"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class BuildParserTests(unittest.TestCase):
    def test_scan_defaults(self) -> None:
        args = build_parser().parse_args(["scan"])
        self.assertEqual(args.format, "markdown")
        self.assertTrue(args.docker)
        self.assertTrue(args.systemd)
        self.assertIsNone(args.output)

    def test_no_docker_flag(self) -> None:
        self.assertFalse(build_parser().parse_args(["scan", "--no-docker"]).docker)

    def test_no_systemd_flag(self) -> None:
        self.assertFalse(build_parser().parse_args(["scan", "--no-systemd"]).systemd)

    def test_format_json(self) -> None:
        self.assertEqual(build_parser().parse_args(["scan", "--format", "json"]).format, "json")

    def test_output_path(self) -> None:
        self.assertEqual(build_parser().parse_args(["scan", "--output", "/tmp/r.md"]).output, "/tmp/r.md")


class MainTests(unittest.TestCase):
    def test_no_subcommand_returns_1(self) -> None:
        self.assertEqual(main([]), 1)

    @patch("portcount.cli.collect_inventory")
    def test_scan_returns_0(self, mock_collect: MagicMock) -> None:
        mock_collect.return_value = _make_minimal_report()
        self.assertEqual(main(["scan"]), 0)

    @patch("portcount.cli.collect_inventory")
    def test_no_docker_passed_to_collect(self, mock_collect: MagicMock) -> None:
        mock_collect.return_value = _make_minimal_report()
        main(["scan", "--no-docker"])
        mock_collect.assert_called_once_with(include_docker=False, include_systemd=True)

    @patch("portcount.cli.collect_inventory")
    def test_no_systemd_passed_to_collect(self, mock_collect: MagicMock) -> None:
        mock_collect.return_value = _make_minimal_report()
        main(["scan", "--no-systemd"])
        mock_collect.assert_called_once_with(include_docker=True, include_systemd=False)

    @patch("portcount.cli.collect_inventory")
    def test_output_file_written(self, mock_collect: MagicMock) -> None:
        mock_collect.return_value = _make_minimal_report()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_path = f.name
        try:
            main(["scan", "--output", output_path])
            self.assertIn("# portcount inventory", Path(output_path).read_text())
        finally:
            Path(output_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
