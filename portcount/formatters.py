from __future__ import annotations

import json
from dataclasses import asdict

from .models import ContainerInfo, ContainerPortMapping, InventoryReport, ListeningSocket


def format_report(report: InventoryReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "table":
        return render_table(report)
    return render_markdown(report)


def render_json(report: InventoryReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def render_markdown(report: InventoryReport) -> str:
    lines = [
        "# portcount inventory",
        "",
        f"- Host: `{report.hostname}`",
        f"- Generated: `{report.generated_at}`",
        f"- Listening endpoints: **{len(report.endpoints)}**",
        f"- Running containers: **{len(report.containers)}**",
        "",
        "## Listening ports",
        "",
    ]

    if report.endpoints:
        lines.extend(
            [
                "| Proto | State | Bind | Port | Process | PID | User | Systemd unit |",
                "| --- | --- | --- | ---: | --- | ---: | --- | --- |",
            ]
        )
        for item in report.endpoints:
            lines.append(
                "| {protocol} | {state} | {bind_address} | {port} | {process_name} | {pid} | {user} | {systemd_unit} |".format(
                    protocol=_md(item.protocol),
                    state=_md(item.state),
                    bind_address=_md(item.bind_address),
                    port=item.port,
                    process_name=_md(item.process_name or "—"),
                    pid=item.pid if item.pid is not None else "—",
                    user=_md(item.user or "—"),
                    systemd_unit=_md(item.systemd_unit or "—"),
                )
            )
    else:
        lines.append("No listening endpoints detected.")

    lines.extend(["", "## Docker containers", ""])
    if report.containers:
        lines.extend(
            [
                "| Container | Image | Status | Port mappings |",
                "| --- | --- | --- | --- |",
            ]
        )
        for container in report.containers:
            lines.append(
                f"| {_md(container.name)} | {_md(container.image)} | {_md(container.status)} | {_md(_container_ports(container))} |"
            )
    else:
        lines.append("No running containers detected.")

    if report.notes:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {_md(note)}" for note in report.notes)

    return "\n".join(lines).rstrip() + "\n"


def render_table(report: InventoryReport) -> str:
    sections = [
        f"portcount inventory :: {report.hostname}",
        f"generated {report.generated_at}",
        "",
        "LISTENING PORTS",
        _plain_table(
            headers=["PROTO", "STATE", "BIND", "PORT", "PROCESS", "PID", "USER", "UNIT"],
            rows=[
                [
                    item.protocol,
                    item.state,
                    item.bind_address,
                    str(item.port),
                    item.process_name or "-",
                    str(item.pid) if item.pid is not None else "-",
                    item.user or "-",
                    item.systemd_unit or "-",
                ]
                for item in report.endpoints
            ],
            empty="No listening endpoints detected.",
        ),
        "",
        "DOCKER CONTAINERS",
        _plain_table(
            headers=["NAME", "IMAGE", "STATUS", "PORTS"],
            rows=[
                [container.name, container.image, container.status, _container_ports(container)]
                for container in report.containers
            ],
            empty="No running containers detected.",
        ),
    ]

    if report.notes:
        sections.extend(["", "NOTES"])
        sections.extend(f"- {note}" for note in report.notes)

    return "\n".join(sections).rstrip() + "\n"


def _plain_table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return empty

    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def render_row(row: list[str]) -> str:
        return " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    divider = "-+-".join("-" * width for width in widths)
    lines = [render_row(headers), divider]
    lines.extend(render_row(row) for row in rows)
    return "\n".join(lines)


def _container_ports(container: ContainerInfo) -> str:
    if container.ports:
        return ", ".join(_mapping_text(mapping) for mapping in container.ports)
    return container.ports_raw or "-"


def _mapping_text(mapping: ContainerPortMapping) -> str:
    if mapping.host_port is None:
        if mapping.container_port is None:
            return mapping.raw
        return f"{mapping.container_port}/{mapping.protocol}"

    if mapping.host_ip:
        host_ip = f"[{mapping.host_ip}]" if ":" in mapping.host_ip and not mapping.host_ip.startswith("[") else mapping.host_ip
        host = f"{host_ip}:{mapping.host_port}"
    else:
        host = str(mapping.host_port)
    if mapping.container_port is None:
        return f"{host}/{mapping.protocol}"
    return f"{host}->{mapping.container_port}/{mapping.protocol}"


def _md(value: str) -> str:
    return value.replace("|", "\\|")
