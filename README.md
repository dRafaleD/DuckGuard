# DuckGuard

[![Build and package](https://github.com/dRafaleD/DuckGuard/actions/workflows/build.yml/badge.svg)](https://github.com/dRafaleD/DuckGuard/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)

**Inspect container configuration before deployment and while containers are running.**

DuckGuard is a Rust CLI that checks Dockerfiles, Docker Compose files, and running Docker container configuration. Each finding includes a rule ID, severity, explanation, and remediation suggestion.

> **Early alpha:** DuckGuard provides configuration review hints, not a security certification. Read the [limitations](#limitations) before relying on its results.

## Two ways to scan

| Mode | Input | Requirements |
| --- | --- | --- |
| Static | Dockerfile and Compose files | DuckGuard executable |
| Runtime | Configuration of running containers | DuckGuard, Docker CLI, and access to the current Docker daemon |

Static analysis runs locally. Runtime analysis uses `docker ps` and `docker container inspect`; it does not start containers or execute commands inside them.

## Quick start

Download a package from [Releases](https://github.com/dRafaleD/DuckGuard/releases), then extract it. Rust and Cargo are **not required** to use a compiled package.

### Windows

Open PowerShell in the extracted directory:

```powershell
.\DuckGuard.exe scan "C:\path\to\project"
.\DuckGuard.exe runtime scan
```

For an optional user-level installation, run the included script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

The script copies the executable to `%LOCALAPPDATA%\Programs\DuckGuard` and adds that directory to your user PATH. Open a new terminal and use `DuckGuard scan .`. Administrator access is not required.

### Linux

Extract the Linux archive and run:

```sh
./DuckGuard scan /path/to/project
./DuckGuard runtime scan
```

Optional installation: `sh install.sh` copies the executable to `~/.local/bin/DuckGuard`. If that directory is missing from PATH, follow the instruction printed by the installer.

Windows EXE files and Linux binaries are separate packages. Linux uses the capitalized command `DuckGuard` after installation.

## Usage

```sh
DuckGuard scan .
DuckGuard scan Dockerfile
DuckGuard scan compose.yml --format json
DuckGuard scan . --severity high --fail-on-findings
DuckGuard runtime scan
DuckGuard runtime scan --format json
DuckGuard runtime scan --severity critical --fail-on-findings
DuckGuard rules
DuckGuard --help
```

Available severity thresholds: `low`, `medium`, `high`, `critical`. The threshold filters both the displayed results and the failure condition.

Example finding from an intentionally privileged Compose service:

```text
[Critical] DG-C001  Privileged service
  compose.yml · service web
  Privileged mode grants broad host privileges.
  Fix: Remove privileged mode and grant only necessary permissions.
```

JSON output contains `findings` and `errors`, plus `scanned_files` for static scans or `scanned_containers` for runtime scans. Review the errors array as well as the findings: a partial scan is not a clean result.

| Exit code | Meaning |
| --- | --- |
| 0 | Scan completed; failure threshold was not triggered |
| 1 | Findings meet the threshold and `--fail-on-findings` is set |
| 2 | Invalid CLI arguments or scan errors, including no supported input files |

## Checks

### Static checks

| Rule | Check |
| --- | --- |
| DG-D001 | Final Dockerfile stage has no explicit user |
| DG-D002 | Final Dockerfile stage explicitly selects root |
| DG-D003 | Base image uses latest or has no tag |
| DG-C001 | Privileged Compose service |
| DG-C002 | Host network or PID namespace |
| DG-C003 | Docker socket mount |
| DG-C004 | Selected powerful capabilities |
| DG-C005 | Port published on all interfaces |
| DG-C006 | Compose service explicitly selects root |

A missing Dockerfile USER instruction is an uncertainty: the base image may already provide a non-root user. A version tag also remains mutable; DG-D003 is a basic tag check, not proof of immutable image provenance.

### Runtime checks

| Rule | Check |
| --- | --- |
| DG-R001 | Privileged container |
| DG-R002 | Host network, PID, or IPC namespace |
| DG-R003 | Selected sensitive host bind mounts, including Docker sockets |
| DG-R004 | Selected powerful added capabilities |
| DG-R005 | Ports published on all interfaces |
| DG-R006 | Root or unspecified Docker startup user |
| DG-R007 | Writable root filesystem |
| DG-R008 | No explicit container memory limit |
| DG-R009 | No explicit container CPU quota |

These checks describe Docker configuration. For example, an entrypoint can switch from the configured startup user to a different process user.

## Limitations

- Dockerfile parsing is line based. Multiline instructions, heredocs, stage inheritance, named build targets, and advanced syntax are not fully supported.
- Compose interpolation, merged files, includes, and overrides are not resolved.
- Discovery recognizes `Dockerfile`, `Dockerfile.*`, `compose.yml`, `compose.yaml`, `docker-compose.yml`, and `docker-compose.yaml`. It skips symlinks and common generated directories.
- Compose findings identify services rather than source line numbers.
- Runtime analysis does not inspect process identities, effective Linux capabilities, traffic, or container files, and does not compare runtime settings with Compose.
- Host firewalls, Docker Desktop networking, user namespace remapping, and parent cgroup limits affect the interpretation of findings.
- Bind-mount and capability checks cover selected patterns, not every dangerous configuration.
- Docker failures and containers disappearing during inspection are reported as errors.
- Local validation has covered Windows with Docker Desktop Linux containers. Native Linux build checks are provided through CI; Windows containers are not validated.

## Build from source

For contributors, install a stable Rust toolchain with Cargo:

```sh
git clone https://github.com/dRafaleD/DuckGuard.git
cd DuckGuard
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The resulting binary is `target/release/duckguard.exe` on Windows or `target/release/duckguard` on Linux.

Run `powershell -File scripts/package.ps1` on Windows to create a portable ZIP in `dist/`. The [build workflow](.github/workflows/build.yml) checks and packages Windows and Linux binaries.

## Project structure

```text
src/
  main.rs       CLI and report output
  discovery.rs  Supported file discovery
  model.rs      Findings, severities, and static reports
  scan.rs       Static configuration checks
  runtime.rs    Docker configuration collection and checks
scripts/        Optional installers and Windows packaging
```

## Contributing

Small, reproducible reports are welcome. Include the DuckGuard version, operating system, command, expected behavior, and a minimal input with secrets removed. For new rules, provide both a configuration that should trigger the rule and one that should not.

## License

[MIT](LICENSE) © 2026 Eren Erdoğan and DuckGuard contributors.

