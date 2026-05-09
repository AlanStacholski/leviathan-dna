# Leviathan DNA
### Behavioral Fingerprinting Engine for Offensive Tool Detection

> 🇧🇷 [Leia em Português](README.pt-BR.md)

> *"Attackers change hashes. They change names. They recompile. But operational behavior remains consistent."*

Leviathan DNA is an experimental **real-time behavioral analysis engine** that profiles running processes by their operational patterns — not by signatures, hashes, or file names. It detects offensive tools by modeling *what they do*, not *what they are*.

Built as a learning and portfolio project exploring the core concepts behind modern EDR (Endpoint Detection & Response) systems.

---

## How It Works

Most antivirus tools ask: *"Is this file known to be malicious?"*

Leviathan DNA asks: *"Does this process behave like an offensive tool?"*

```
Windows Kernel
     │
     ▼
  Sysmon (ETW driver)          ← captures process creation, network, LSASS access
     │
     ▼
  Event Collector              ← real-time ETW subscription via Win32 API
     │
     ▼
  Process Context Table        ← maintains behavioral state per PID
     │
     ▼
  Rule Engine                  ← evaluates behavioral rules, accumulates score
     │
     ▼
  Classification               ← BENIGN / SUSPICIOUS / OFFENSIVE-LIKE / CRITICAL
     │
     ▼
  Live Dashboard               ← real-time terminal UI + incident history
```

A process named `chrome.exe` that opens a handle to `lsass.exe` and spawns encoded PowerShell commands scores high for Mimikatz-like behavior — regardless of its name or hash.

---

## Detection Capabilities

Each rule maps to a [MITRE ATT&CK](https://attack.mitre.org/) technique and includes contextual explanation of *why* the behavior is suspicious.

| Rule | MITRE | Weight | What it detects |
|---|---|---|---|
| `lsass_access` | T1003.001 | +50 | Process opening a handle to lsass.exe (credential dumping) |
| `suspicious_parent_spawn` | T1566 | +35 | Shell spawned by an unexpected parent process |
| `encoded_powershell` | T1059.001 | +30 | PowerShell executing Base64-encoded commands |
| `ldap_enumeration` | T1087.002 | +20 | Connections to LDAP ports (domain reconnaissance) |
| `dns_recon` | T1018 | +15 | High-volume sequential DNS queries |

### Classification Thresholds

```
Score  0–29   →  BENIGN
Score 30–59   →  SUSPICIOUS
Score 60–89   →  OFFENSIVE-LIKE
Score 90+     →  CRITICAL
```

---

## Live Dashboard

The engine runs a real-time terminal dashboard that updates every second, showing active processes with elevated scores and a persistent incident history with full behavioral explanations.

```
┌─ Leviathan DNA — Behavioral Fingerprinting Engine ──────────────────────────┐
│  Events captured: 847    Incidents detected: 3    Updated: 14:55:01         │
├─ ● Active processes ────────────────────────────────────────────────────────┤
│  PID    Process         Parent      Score  Status                           │
│  20928  powershell.exe  cmd.exe     65     OFFENSIVE-LIKE                   │
├─ ⚑ Incident history ────────────────────────────────────────────────────────┤
│  14:53:01  powershell.exe  Score: 65  OFFENSIVE-LIKE                        │
│                                                                             │
│  ▶ encoded_powershell  +30pts  [T1059.001]                                  │
│    What is happening:                                                       │
│    PowerShell is executing a Base64-encoded command, concealing its real    │
│    content from surface-level log inspection.                               │
│                                                                             │
│    In offensive practice:                                                   │
│    Mimikatz, Empire, and Cobalt Strike use this technique to execute        │
│    payloads without writing scripts to disk.                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
leviathan-dna/
│
├── collector/
│   └── event_listener.py      # Real-time ETW subscription (Win32 API)
│
├── engine/
│   ├── process_context.py     # Per-process behavioral state model
│   ├── rule_engine.py         # Rule orchestration and score evaluation
│   ├── whitelist.py           # Trusted process and parent definitions
│   └── rules/
│       ├── credential_access.py   # LSASS access detection
│       ├── execution.py           # Shell and encoding-based rules
│       └── discovery.py           # Network recon and DNS rules
│
├── output/
│   ├── alert_handler.py       # Incident registration and JSON logging
│   ├── state_writer.py        # Shared state serialization (1s interval)
│   └── dashboard.py           # Rich terminal UI (separate process)
│
└── main.py                    # Engine entry point
```

### Key Design Decisions

**Rule-based scoring before ML** — deliberately starting with explicit behavioral rules rather than statistical models. This forces a deep understanding of each offensive technique and produces transparent, explainable detections. ML is the logical next step once the behavioral vocabulary is well-defined.

**Per-process context accumulation** — each PID maintains its full event history and an incremental score. Rules re-evaluate on every new event, allowing the score to escalate as behavior compounds.

**Sysmon as the kernel interface** — rather than writing a kernel driver (a multi-month effort), Sysmon handles low-level event capture. The engine focuses on the detection logic, which is the architecturally interesting layer.

**Process isolation for the dashboard** — the UI runs as a separate process reading a shared JSON state file, keeping the collection pipeline unblocked regardless of rendering time.

---

## Getting Started

### Prerequisites

- Windows 10/11 (the engine uses Windows ETW and Win32 APIs)
- Python 3.10+
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed with a behavioral config

### Install Sysmon

Download [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) and the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config), then run in an elevated PowerShell:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Install dependencies

```powershell
pip install pywin32 rich
```

### Run

```powershell
# Must be run as Administrator
python main.py
```

The engine starts in the current terminal. The dashboard opens automatically in a second window.

---

## Simulating Detections

You can trigger real detections without any offensive tools using built-in Windows capabilities:

```powershell
# Triggers: encoded_powershell (+30)
$cmd = "Write-Host 'Leviathan Test'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded

# Triggers: dns_recon (+15) — 15 sequential DNS queries
1..15 | ForEach-Object {
    Resolve-DnsName "host$_.test.local" -ErrorAction SilentlyContinue
}
```

---

## Concepts Behind the Project

This project is a hands-on implementation of concepts used by commercial EDR platforms:

**Behavioral heuristics** — instead of signature matching, rules describe operational patterns. This is how CrowdStrike Falcon, SentinelOne, and Microsoft Defender for Endpoint approach detection at their core.

**Parent-child process relationships** — the Windows process tree encodes intent. A Word document spawning `cmd.exe` is not the same as a terminal spawning `cmd.exe`, even if the resulting process is identical.

**ETW (Event Tracing for Windows)** — the kernel-level telemetry pipeline that feeds data to Sysmon and, through it, to this engine. Understanding ETW is foundational for Windows endpoint security engineering.

**MITRE ATT&CK mapping** — each rule is anchored to a documented adversary technique, connecting detections to real-world threat actor behavior.

---

## Roadmap

- [ ] Process termination cleanup (remove exited PIDs from active table)
- [ ] Behavioral similarity scoring across multiple processes
- [ ] Session persistence (reload incident history on restart)
- [ ] Additional rules: CreateRemoteThread, WMI execution, pipe-based C2 patterns
- [ ] Web dashboard (FastAPI + WebSocket)
- [ ] YARA-style rule definition format

---

## Author

**Alan Jones Stacholski Júnior**
Software Engineering student | Cybersecurity postgraduate (UTFPR)
Curitiba, Brazil

[GitHub](https://github.com/AlanStacholski) · [LinkedIn](https://www.linkedin.com/in/alanjr/) · [stacholski.com.br](https://stacholski.com.br)

---

*"The fear of the Lord is the beginning of wisdom." — Proverbs 9:10*