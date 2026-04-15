# Perfodia — Docker Guide

Run Perfodia in a container for lab testing workflows.

> Authorized lab use only.

## Build

```bash
docker build -t perfodia .
docker build -t perfodia:minimal --target minimal .
```

## Basic Usage

```bash
# Show framework CLI help
docker run --rm perfodia --help

# Validate tool dependencies
docker run --rm perfodia --check-tools

# Recon workflow
docker run --rm --net=host perfodia -t 192.168.1.100 -m recon -v

# Full workflow (dry-run)
docker run --rm --net=host perfodia -t 192.168.1.100 -m full --dry-run -v
```

## Resume Example

```bash
docker run --rm --net=host \
  -v "$(pwd)/reports:/opt/perfodia/reports" \
  perfodia -t 192.168.1.100 -m full --session 20260410_120000 --resume -v
```

## Target List Example

```bash
docker run --rm --net=host \
  -v "$(pwd)/targets.txt:/opt/perfodia/targets.txt:ro" \
  perfodia -tL /opt/perfodia/targets.txt -m scan --enum -v
```

## Nmap Override Example

```bash
docker run --rm --net=host perfodia \
  -t 192.168.1.100 -m scan \
  --nmap-scan-type sT \
  --nmap-extra '-Pn --top-ports 2000' \
  --nmap-scripts 'safe,vuln' \
  -v
```

## Persist Reports

```bash
docker run --rm --net=host \
  -v "$(pwd)/reports:/opt/perfodia/reports" \
  perfodia -t 192.168.1.100 -m full --report-format all -v
```

## Custom Configs

```bash
docker run --rm --net=host \
  -v "$(pwd)/configs:/opt/perfodia/configs:ro" \
  -v "$(pwd)/reports:/opt/perfodia/reports" \
  perfodia -t 192.168.1.100 -m full -c /opt/perfodia/configs/default.yaml -v
```

## Compose

```bash
docker compose build
docker compose run --rm perfodia --check-tools
docker compose run --rm perfodia -t 192.168.1.100 -m recon -v
docker compose down
```

## Notes

- Use `--net=host` for best scanner behavior.
- For rootless patterns, pass `--nmap-scan-type sT`.
- `--resume` requires `--session <existing_session_name>`.
- You can pass compatibility flags like `--nmap-extra` and `--nmap-raw`.
