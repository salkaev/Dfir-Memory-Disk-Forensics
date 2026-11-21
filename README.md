# DFIR — Memory & Disk Forensics Investigations

A collection of hands-on **Digital Forensics and Incident Response (DFIR)** investigation reports covering Windows and Linux memory acquisition triage, rootkit and kernel module forensics, multi-stage malware execution, static PE analysis, and disk image forensics. Each report follows a structured SOC/IR workflow: artifact acquisition and triage, timeline reconstruction, Indicator of Compromise (IoC) extraction, MITRE ATT&CK mapping, and actionable remediation.

---

## Investigation Index

| Lab / Case | Domain | Key Artifacts & Malware | Primary Tools | Report |
|------------|--------|-------------------------|---------------|--------|
| **RedLine Lab** *(CyberDefenders)* | Windows Memory Forensics | **RedLine Stealer** (`oneetx.exe`), RWX code injection (`MZ` header), Outline VPN tunnel vs. HTTP C2 (`77.91.124.20:80`) | Volatility 3 (`pslist`, `malfind`, `netscan`, `filescan`), `strings` | [RedLine Lab.md](RedLine%20Lab/RedLine%20Lab.md) |
| **Reveal Lab** *(CyberDefenders)* | Windows Memory Forensics | **StrelaStealer** multi-stage chain, hidden PowerShell, WebDAV mount (`\\45.9.74.32@8888\davwwwroot\`), remote DLL execution (`3435.dll,entry`) | Volatility 3 (`pstree`, `sessions`), MITRE ATT&CK | [Reveal Lab.md](Reveal%20Lab/Reveal%20Lab.md) |
| **Insider Lab** *(CyberDefenders)* | Linux Disk Forensics | Rogue Kali Linux workstation (`Horcrux.E01`), `mimikatz_trunk.zip`, `.bash_history`, `auth.log` (`su`/`visudo`), target desktop capture (`aylmao.exe` / `flightsim`) | FTK Imager, Linux CLI (`md5sum`, `binwalk`), log analysis | [Insider Lab.md](Insider%20Lab/Insider%20Lab.md) |
| **Ramnit Lab** *(CyberDefenders)* | Windows Memory & Static PE | **Ramnit** file infector masquerading as `ChromeSetup.exe` (unsigned), C2 (`58.64.204.181:5202`), hijacked PE entry point (`EP = F0000`) | Volatility 3 (`pstree`, `cmdline`, `netscan`, `dumpfiles`), PE-bear, VirusTotal, IPinfo | [Ramnit Lab.md](Ramnit%20Lab/Ramnit%20Lab.md) |
| **Seized Lab** *(CyberDefenders)* | Linux Memory Forensics | CentOS 7 compromise (`dump.mem`), `PythonBackup` / Pastebin stager, `LiME` module, `ncat` backdoor (`:12345`), `/etc/rc.local` SSH key persistence, syscall `88` hook & unsigned module `sysemptyrect` (`crc65_key`) | Volatility 3 (`psaux`, `sockstat`, `lsmod`, `check_syscall`), `strings`, CyberChef | [Seized Lab.md](Seized%20Lab/Seized%20Lab.md) |
| **BlackEnergy Lab** *(CyberDefenders)* | Windows Memory Forensics | Windows XP SP3 rootkit triage (`CYBERDEF-567078-20230213-171333.raw`), `rootkit.exe`, driver artifact `str.sys`, unlinked module at `0x980000` in `svchost.exe` (PID `880`) | Volatility 3 (`windows.info`, `pslist`, `ldrmodules`), `awk` | [BlackEnergy Lab.md](BlackEnergy%20Lab/BlackEnergy%20Lab.md) |

---

## Methodology & Report Structure

Every investigation in this repository is documented using a consistent incident-response format:

1. **Executive Summary** – scope, compromised host/user context, root cause, and attribution.
2. **Investigation Workflow** – step-by-step analytical sequence from initial triage to artifact verification.
3. **Technical Walkthrough** – exact commands, forensic tool outputs, and annotated screenshots.
4. **Indicators of Compromise (IoCs)** – file hashes, paths, C2 IP addresses, ports, kernel artifacts, and URLs ready for SIEM/EDR blocking.
5. **MITRE ATT&CK Mapping** – adversary behaviors mapped to specific technique and sub-technique IDs.
6. **Remediation & Lessons Learned** – containment actions, credential hygiene, and detection engineering recommendations.

---

## Tooling & Core Competencies

* **Windows Memory Forensics:** Volatility 3 (`windows.info`, `windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.malfind`, `windows.malware.ldrmodules`, `windows.netscan`, `windows.filescan`, `windows.sessions`, `windows.dumpfiles`)
* **Linux Memory Forensics:** Volatility 3 (`linux.psaux`, `linux.sockstat`, `linux.lsmod`, `linux.check_syscall`), process dump string extraction, LiME artifact identification
* **Disk & File System Forensics:** FTK Imager (`E01`, `ext4`, `NTFS`), Linux log & shell artifact triage (`/var/log/auth.log`, `/var/log/apache2/`, `.bash_history`), `binwalk`, `strings`, `awk`
* **Malware & Static PE Triage:** PE-bear (PE headers, section anomalies, entry point inspection), Authenticode signature verification, CyberChef
* **Threat Intelligence & Enrichment:** VirusTotal, IPinfo, MITRE ATT&CK

---

## Repository Structure

```text
Dfir-Memory-Disk-Forensics/
├── README.md
├── RedLine Lab/
│   ├── RedLine Lab.md
│   └── screenshots/
├── Reveal Lab/
│   ├── Reveal Lab.md
│   └── screenshots/
├── Insider Lab/
│   ├── Insider Lab.md
│   └── screenshots/
├── Ramnit Lab/
│   ├── Ramnit Lab.md
│   └── screenshots/
├── Seized Lab/
│   ├── Seized Lab.md
│   └── screenshots/
└── BlackEnergy Lab/
    ├── BlackEnergy Lab.md
    └── screenshots/