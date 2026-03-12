from __future__ import annotations

import json
import os
import pwd
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .models import ContainerInfo, ContainerPortMapping, InventoryReport, ListeningSocket

_PROCESS_RE = re.compile(r'"(?P<name>[^\"]+)",pid=(?P<pid>\d+)')
_UNIT_RE = re.compile(r'([A-Za-z0-9_.@-]+\.(?:service|socket|scope|mount))')


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def split_host_port(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if not value:
        return "", None

    if value.startswith("[") and "]:" in value:
        address, port_text = value[1:].rsplit("]:", 1)
        return address, _safe_int(port_text)

    if value.count(":") >= 2 and value.rsplit(":", 1)[1].isdigit():
        address, port_text = value.rsplit(":", 1)
        return address, _safe_int(port_text)

    if ":" in value:
        address, port_text = value.rsplit(":", 1)
        return address, _safe_int(port_text)

    return value, None


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_process_field(value: str | None) -> tuple[int | None, str | None]:
    if not value:
        return None, None

    matches = [(match.group("name"), int(match.group("pid"))) for match in _PROCESS_RE.finditer(value)]
    if not matches:
        return None, None

    preferred = next((item for item in matches if item[0] not in {"systemd", "init"}), matches[0])
    return preferred[1], preferred[0]


def lookup_user(pid: int | None) -> str | None:
    if pid is None:
        return None

    try:
        uid = Path(f"/proc/{pid}").stat().st_uid
        return pwd.getpwuid(uid).pw_name
    except (FileNotFoundError, PermissionError, KeyError, ProcessLookupError):
        return None


def parse_unit_from_cgroup(text: str) -> str | None:
    matches = _UNIT_RE.findall(text)
    if not matches:
        return None

    for suffix in (".service", ".socket", ".scope", ".mount"):
        preferred = next((item for item in matches if item.endswith(suffix)), None)
        if preferred:
            return preferred
    return matches[0]


def infer_systemd_unit(pid: int | None) -> str | None:
    if pid is None:
        return None

    try:
        text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="ignore")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    return parse_unit_from_cgroup(text)


def parse_ss_line(line: str, include_systemd: bool = True) -> ListeningSocket | None:
    parts = line.split(maxsplit=6)
    if len(parts) < 6:
        return None

    protocol, state, _recv_q, _send_q, local_address, _peer = parts[:6]
    process_field = parts[6] if len(parts) > 6 else ""
    bind_address, port = split_host_port(local_address)
    if port is None:
        return None

    pid, process_name = parse_process_field(process_field)
    user = lookup_user(pid)
    unit = infer_systemd_unit(pid) if include_systemd else None
    return ListeningSocket(
        protocol=protocol,
        state=state,
        bind_address=bind_address,
        port=port,
        pid=pid,
        process_name=process_name,
        user=user,
        systemd_unit=unit,
        source="ss",
    )


def parse_netstat_line(line: str, include_systemd: bool = True) -> ListeningSocket | None:
    parts = line.split()
    if len(parts) < 6 or parts[0].startswith("Active") or parts[0].startswith("Proto"):
        return None

    protocol = parts[0]
    local_address = parts[3]
    bind_address, port = split_host_port(local_address)
    if port is None:
        return None

    if protocol.startswith("tcp"):
        state = parts[5]
        program_field = parts[6] if len(parts) > 6 else ""
    else:
        state = "UNCONN"
        program_field = parts[5] if len(parts) > 5 else ""

    pid = None
    process_name = None
    if "/" in program_field:
        pid_text, process_name = program_field.split("/", 1)
        pid = _safe_int(pid_text)

    user = lookup_user(pid)
    unit = infer_systemd_unit(pid) if include_systemd else None
    return ListeningSocket(
        protocol=protocol,
        state=state,
        bind_address=bind_address,
        port=port,
        pid=pid,
        process_name=process_name or None,
        user=user,
        systemd_unit=unit,
        source="netstat",
    )


def collect_listening_sockets(include_systemd: bool = True) -> tuple[list[ListeningSocket], list[str]]:
    notes: list[str] = []

    if shutil.which("ss"):
        completed = _run_command(["ss", "-lntupH"])
        if completed.returncode == 0:
            sockets = [
                parsed
                for line in completed.stdout.splitlines()
                if (parsed := parse_ss_line(line, include_systemd=include_systemd)) is not None
            ]
            if completed.stderr.strip():
                notes.append(f"ss reported: {completed.stderr.strip()}")
            return _sort_sockets(sockets), notes
        notes.append(f"ss failed with exit code {completed.returncode}; trying netstat.")

    if shutil.which("netstat"):
        completed = _run_command(["netstat", "-lntupn"])
        if completed.returncode == 0:
            sockets = [
                parsed
                for line in completed.stdout.splitlines()
                if (parsed := parse_netstat_line(line, include_systemd=include_systemd)) is not None
            ]
            return _sort_sockets(sockets), notes
        notes.append(f"netstat failed with exit code {completed.returncode}.")
    else:
        notes.append("netstat is not installed.")

    notes.append("No supported socket inspection tool was available.")
    return [], notes


def _sort_sockets(sockets: list[ListeningSocket]) -> list[ListeningSocket]:
    return sorted(sockets, key=lambda item: (item.port, item.protocol, item.bind_address, item.process_name or ""))


def parse_docker_port_mappings(value: str) -> list[ContainerPortMapping]:
    if not value:
        return []

    mappings: list[ContainerPortMapping] = []
    for chunk in [item.strip() for item in value.split(",") if item.strip()]:
        if "->" in chunk:
            host_side, container_side = chunk.split("->", 1)
            if "/" in container_side:
                container_port_text, protocol = container_side.split("/", 1)
            else:
                container_port_text, protocol = container_side, "tcp"
            host_ip, host_port = split_host_port(host_side)
            mappings.append(
                ContainerPortMapping(
                    host_ip=host_ip or None,
                    host_port=host_port,
                    container_port=_safe_int(container_port_text),
                    protocol=protocol,
                    raw=chunk,
                )
            )
            continue

        port_text, protocol = chunk.split("/", 1) if "/" in chunk else (chunk, "tcp")
        mappings.append(
            ContainerPortMapping(
                host_ip=None,
                host_port=None,
                container_port=_safe_int(port_text),
                protocol=protocol,
                raw=chunk,
            )
        )
    return mappings


def collect_docker_containers() -> tuple[list[ContainerInfo], list[str]]:
    notes: list[str] = []
    if not shutil.which("docker"):
        notes.append("docker is not installed.")
        return [], notes

    completed = _run_command(["docker", "ps", "--format", "{{json .}}"])
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"exit code {completed.returncode}"
        notes.append(f"docker ps failed: {message}")
        return [], notes

    containers: list[ContainerInfo] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        ports_raw = data.get("Ports", "")
        containers.append(
            ContainerInfo(
                name=data.get("Names", ""),
                image=data.get("Image", ""),
                status=data.get("Status", ""),
                ports_raw=ports_raw,
                ports=parse_docker_port_mappings(ports_raw),
            )
        )

    containers.sort(key=lambda item: item.name)
    return containers, notes


def collect_inventory(*, include_docker: bool = True, include_systemd: bool = True) -> InventoryReport:
    endpoints, notes = collect_listening_sockets(include_systemd=include_systemd)
    containers: list[ContainerInfo] = []

    if include_docker:
        containers, docker_notes = collect_docker_containers()
        notes.extend(docker_notes)

    if include_systemd and shutil.which("systemctl") is None:
        notes.append("systemctl is not installed; systemd units are inferred from /proc when possible.")

    return InventoryReport(
        hostname=socket.gethostname(),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        endpoints=endpoints,
        containers=containers,
        notes=_dedupe_notes(notes),
    )


def _dedupe_notes(notes: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for note in notes:
        clean = note.strip()
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result
