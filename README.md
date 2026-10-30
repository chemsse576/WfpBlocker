# WfpBlocker

EDR/AV network traffic blocker using the Windows Filtering Platform (WFP) for **authorized** penetration testing engagements.

> **Disclaimer** — This tool is provided for **authorized security assessments, educational purposes, and defensive research only**. Use it exclusively on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

## Overview

WfpBlocker creates persistent WFP filters that block outbound network traffic for EDR/AV processes. This prevents security products from sending telemetry, alerts, or sample submissions to their cloud backends during an engagement.

The tool registers filters under a custom WFP provider that blends in with built-in Windows providers. Filters are persistent across reboots and can be cleanly reverted.

## Features

- **94 EDR/AV signatures** covering major vendors (Defender/MDE, CrowdStrike, SentinelOne, Carbon Black, Cortex XDR, Elastic, Symantec, Cylance, Trend Micro, ESET, Sophos, Bitdefender, Kaspersky, McAfee/Trellix, FireEye, Fortinet, Cybereason, Tanium, HarfangLab, Wazuh, WithSecure, Rapid7, Malwarebytes, Sysmon)
- Blocks both **IPv4 and IPv6** outbound connections per EDR process
- **Persistent** filters that survive reboots
- Clean **revert** to remove all custom filters and the provider
- List active custom filters with associated app paths

## Usage

Requires **Administrator** privileges.

```
WfpBlocker.exe -enumSec      Enumerate running EDR/AV processes
WfpBlocker.exe -blockSec     Add WFP block filters for detected EDR processes
WfpBlocker.exe -listWFP      List our custom WFP filters
WfpBlocker.exe -revert       Remove all custom filters and provider
WfpBlocker.exe -listProc     List all running processes
WfpBlocker.exe -h            Help
```

### Typical workflow

```
WfpBlocker.exe -enumSec      # 1. See what's running
WfpBlocker.exe -blockSec     # 2. Block their traffic
WfpBlocker.exe -listWFP      # 3. Verify filters are active
# ... do your thing ...
WfpBlocker.exe -revert       # 4. Clean up when done
```

## Build

Requires Visual Studio (2022/2026) with the **C++ Desktop** workload.

```
build.bat
```

Or manually:

```
mkdir build && cd build
cmake -G "Visual Studio 18 2026" -A x64 ..
cmake --build . --config Release
```

Output: `build\Release\WfpBlocker.exe`

- Static CRT (`/MT`) — no runtime dependencies
- x64 only
- Single binary

## How it works

1. Snapshots running processes and matches against the EDR signature list
2. For each match, retrieves the full image path and converts it to an NT device path
3. Creates persistent WFP filters on `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `V6` layers that block outbound connections for that application
4. Registers a custom WFP provider to group all filters for clean removal

## Legal

This project is intended for use by security professionals during **authorized** engagements such as:

- Penetration tests with a signed scope/contract
- Red team exercises with explicit authorization
- Security audits and compliance assessments
- Personal lab environments and CTF challenges
- Defensive security research and hardening validation

**Do not use this tool on systems without proper authorization.** The author is not responsible for any damage or legal consequences resulting from misuse.

## License

MIT
