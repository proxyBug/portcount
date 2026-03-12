from __future__ import annotations

import unittest
from unittest.mock import patch

from portcount.collectors import (
    parse_docker_port_mappings,
    parse_ss_line,
    parse_unit_from_cgroup,
    split_host_port,
)
from portcount.formatters import render_markdown
from portcount.models import ContainerInfo, ContainerPortMapping, InventoryReport, ListeningSocket


class SplitHostPortTests(unittest.TestCase):
    def test_ipv4(self) -> None:
        self.assertEqual(split_host_port("0.0.0.0:22"), ("0.0.0.0", 22))

    def test_ipv6(self) -> None:
        self.assertEqual(split_host_port("[::]:443"), ("::", 443))

    def test_ipv6_without_brackets(self) -> None:
        self.assertEqual(split_host_port(":::80"), ("::", 80))


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


if __name__ == "__main__":
    unittest.main()
