# Perfodia — Network Penetration Testing Framework

Perfodia is a modular Python framework for authorized lab penetration testing workflows.
It supports phase-based execution (`recon`, `scan`, `enum`, `webapp`, `exploit`, `ad`, `crack`, `post`),
session checkpoints, scope control, vulnerability scoring, and report generation.

> **Authorized lab use only.**

## Current CLI Capabilities

- Run full workflow: `-m full`
- Run one mode: `-m recon|scan|webapp|exploit|ad|crack|post`
- Run explicit module chain: `--modules recon,scan,enum`
- Run scan + enum shortcut: `-m scan --enum`
- Validate dependencies: `--check-tools`
- Generate config interactively: `--init`
- Resume workflow: `--resume --session <session_name>`
- Dry-run external commands: `--dry-run`
- Override nmap behavior: `--nmap-extra`, `--nmap-raw`, `--nmap-scan-type`, `--nmap-scripts`
- Select report output: `--report-format html|json|md|pdf|all`
- Load targets from file: `-tL targets.txt`

## Quick Start

```bash
pip install -r requirements.txt
python3 perfodia.py --check-tools
python3 perfodia.py -t 192.168.1.100 -m recon -v
python3 perfodia.py -t 192.168.1.100 -m full --dry-run -v
```

## Installation

### 1) System tools

```bash
chmod +x install_deps.sh
sudo bash install_deps.sh --dry-run
sudo bash install_deps.sh --full
```

### 2) Python dependencies

```bash
pip install -r requirements.txt
```

## Configuration

- Default config: `configs/default.yaml`

Use custom config:

```bash
python3 perfodia.py -t 192.168.1.100 -m full -c configs/default.yaml
```

Generate one interactively:

```bash
python3 perfodia.py --init
```

## Resume / Session Rules

To resume, you must provide the original session name:

```bash
python3 perfodia.py -t 192.168.1.100 -m full --session 20260410_120000 --resume
```

If a checkpoint is missing for that session, the command exits with an error.

## Modes and Module Chains

| Mode | Modules |
|---|---|
| recon | recon |
| scan | scan |
| webapp | scan, webapp |
| exploit | scan, enum, exploit |
| ad | scan, enum, ad |
| crack | crack |
| post | post |
| full | recon, scan, enum, webapp, exploit, ad, crack, post |

## Notes on Nmap Overrides

- `--nmap-extra`: append sanitized options to default scanning args.
- `--nmap-raw`: replace default scan flags with sanitized raw flags.
- `--nmap-scan-type`: override scan type (example: `sT`).
- `--nmap-scripts`: override script selection used in vuln-script phase.

## Docker

See `Docker Guide.md` for container execution examples.

## Project Structure

- `perfodia.py`
- `configs/`
- `modules/`
- `utils/`
- `install_deps.sh`
- `Dockerfile`
- `docker-compose.yml`
- `tests/`

## Testing

```bash
pytest -q
ruff check .
mypy .
```

## License

MIT (see `LICENSE`).
