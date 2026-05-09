# engine/whitelist.py

# Processos que normalmente spawnам shells por razões legítimas
TRUSTED_PARENTS = {
    "explorer.exe",        # Windows shell
    "services.exe",        # Service Control Manager
    "svchost.exe",         # Host de serviços do Windows
    "lsass.exe",           # Local Security Authority
    "csrss.exe",           # Client Server Runtime
    "wininit.exe",         # Windows Initialization
    "winlogon.exe",        # Windows Logon
    "taskhostw.exe",       # Task Host
    "taskeng.exe",         # Task Scheduler Engine
    "msiexec.exe",         # Windows Installer
    "TrustedInstaller.exe",
    # IDEs e editores — ajuste conforme o que você usa
    "code.exe",            # VSCode
    "cursor.exe",          # Cursor
    "idea64.exe",          # IntelliJ
    "devenv.exe",          # Visual Studio
    # Terminais
    "WindowsTerminal.exe",
    "wt.exe",
    "conhost.exe",
    "mintty.exe",          # Git Bash
}

# PIDs de sistema que nunca devem ser analisados
TRUSTED_PIDS = {0, 4}  # System Idle Process e System

# Processos que por si só não são suspeitos
TRUSTED_PROCESS_NAMES = {
    "svchost.exe",
    "RuntimeBroker.exe",
    "SearchIndexer.exe",
    "WmiPrvSE.exe",
    "spoolsv.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "conhost.exe",
}


def is_trusted_parent(parent_name: str) -> bool:
    return parent_name.lower() in {p.lower() for p in TRUSTED_PARENTS}


def is_trusted_process(process_name: str) -> bool:
    return process_name.lower() in {p.lower() for p in TRUSTED_PROCESS_NAMES}


def is_trusted_pid(pid: int) -> bool:
    return pid in TRUSTED_PIDS