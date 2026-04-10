# Perfodia — Network Penetration Testing Framework

Perfodia is a modular Python framework for authorized lab penetration testing workflows.
It supports phase-based execution (recon, scan, enum, webapp, exploit, ad, crack, post),
shared session state, scope control, and tool orchestration.

> **Authorized lab use only.**

## Current CLI Capabilities

- Run a full workflow: `-m full`
- Run a specific mode: `-m recon|scan|webapp|exploit|ad|crack|post`
- Run explicit module chains: `--modules recon,scan,enum`
- Run scan + enum shortcut: `-m scan --enum`
- Validate dependencies: `--check-tools`
- Generate config file interactively: `--init`
- Resume from checkpoint: `--resume --session <name>`
- Dry run command generation: `--dry-run`

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

Default config: `configs/default.yaml`

Use custom config:

```bash
python3 perfodia.py -t 192.168.1.100 -m full -c configs/default.yaml
```

Generate one interactively:

```bash
python3 perfodia.py --init
```

## Modes and Module Chains

| Mode | Modules |
|------|---------|
| recon | recon |
| scan | scan |
| webapp | scan, webapp |
| exploit | scan, enum, exploit |
| ad | scan, enum, ad |
| crack | crack |
| post | post |
| full | recon, scan, enum, webapp, exploit, ad, crack, post |

## Important Notes

- Some tools are optional; missing optional tools do not block execution.
- Required tools include at least `nmap` and `curl` (check with `--check-tools`).
- `--nmap-extra`, `--nmap-raw`, `--nmap-scan-type`, and `--nmap-scripts` are accepted CLI inputs for compatibility with existing runbooks.

## Docker

See `Docker Guide.md` for container execution examples.

## Project Structure

```text
perfodia.py
configs/
modules/
utils/
install_deps.sh
Dockerfile
docker-compose.yml
tests/
```

## Testing

```bash
pytest -q
ruff check .
mypy .
```

## License

MIT (see `LICENSE`).
