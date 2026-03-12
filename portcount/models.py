from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ListeningSocket:
    protocol: str
    state: str
    bind_address: str
    port: int
    pid: int | None = None
    process_name: str | None = None
    user: str | None = None
    systemd_unit: str | None = None
    source: str = "ss"


@dataclass(slots=True)
class ContainerPortMapping:
    host_ip: str | None
    host_port: int | None
    container_port: int | None
    protocol: str
    raw: str


@dataclass(slots=True)
class ContainerInfo:
    name: str
    image: str
    status: str
    ports_raw: str = ""
    ports: list[ContainerPortMapping] = field(default_factory=list)


@dataclass(slots=True)
class InventoryReport:
    hostname: str
    generated_at: str
    endpoints: list[ListeningSocket] = field(default_factory=list)
    containers: list[ContainerInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
