# portcount

> Turn any Linux host into a living inventory of ports, services, and containers.

`portcount` is a small Linux-first CLI for one deceptively common problem: **what is actually listening on this box, and how do I explain it to my future self?**

Instead of bouncing between `ss`, `docker ps`, `systemctl`, shell history, and old notes, `portcount` turns the local host into a compact report you can read, diff, or commit.

## Why this exists

A machine starts simple, then grows sharp edges:

- port `3001` belongs to something you set up at 2 a.m.
- Docker is publishing a service you barely remember
- one PID maps to a unit, another lives outside systemd
- your "temporary" note is now six weeks old

`portcount` gives you one inventory with:

- listening TCP and UDP sockets
- best-effort process and PID attribution
- best-effort user lookup
- best-effort systemd unit inference from `/proc`
- Docker container port mappings
- Markdown, table, or JSON output

## Install

### Run directly

```bash
python -m portcount scan
```

### Install locally with pip

```bash
python -m pip install .
portcount scan
```

## Usage

```bash
python -m portcount scan
python -m portcount scan --format markdown
python -m portcount scan --format table
python -m portcount scan --format json
python -m portcount scan --output SERVICES.md
python -m portcount scan --no-docker
python -m portcount scan --no-systemd
```

## Example

### Markdown

```markdown
# portcount inventory

- Host: `infra-01`
- Generated: `2026-03-12T11:55:00+00:00`
- Listening endpoints: **4**
- Running containers: **2**

## Listening ports

| Proto | State | Bind | Port | Process | PID | User | Systemd unit |
| --- | --- | --- | ---: | --- | ---: | --- | --- |
| tcp | LISTEN | 0.0.0.0 | 22 | sshd | 1234 | root | ssh.service |
| tcp | LISTEN | 127.0.0.1 | 5432 | postgres | 3321 | postgres | postgresql.service |
| tcp | LISTEN | 0.0.0.0 | 3001 | node | 8812 | app | — |
| udp | UNCONN | 127.0.0.53%lo | 53 | systemd-resolve | 611 | systemd-resolve | systemd-resolved.service |

## Docker containers

| Container | Image | Status | Port mappings |
| --- | --- | --- | --- |
| nginx | nginx:1.27 | Up 2 hours | 0.0.0.0:8080->80/tcp |
| grafana | grafana/grafana:11.0 | Up 4 days | 3000/tcp |
```

### Turn it into living documentation

```bash
python -m portcount scan --output SERVICES.md
```

That one file is often enough to answer:

- what is exposed publicly
- what only binds on localhost
- which process owns which port
- which containers are publishing host ports

## Output modes

### `--format markdown`
Best for documentation, runbooks, and GitHub repos.

### `--format table`
Best for terminal inspection.

### `--format json`
Best for piping into scripts, dashboards, or inventory workflows.

## Notes on accuracy

`portcount` aims for elegant usefulness, not false certainty.

- Process names and PIDs depend on what `ss` or `netstat` can see in your current privilege context.
- systemd unit attribution is inferred from `/proc/<pid>/cgroup`, so it is best-effort.
- Docker data comes from `docker ps`, so it reflects what the Docker CLI can access.
- If `ss` is missing, `portcount` falls back to `netstat` when available.

## Development

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

Run the CLI locally:

```bash
python -m portcount scan --format markdown
python -m portcount scan --format json
```

## License

MIT
