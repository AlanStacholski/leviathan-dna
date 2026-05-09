import json
import time

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.layout import Layout
from rich.panel import Panel
from rich.columns import Columns
from rich import box

STATE_FILE = "leviathan_state.json"
console = Console()

COLOR_MAP = {
    "CRITICAL":       "bold red",
    "OFFENSIVE-LIKE": "bold magenta",
    "SUSPICIOUS":     "bold yellow",
    "BENIGN":         "green",
}

MITRE_COLOR = "bold cyan"


def read_state() -> dict:
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {
            "processes": [],
            "incidents": [],
            "event_counter": {"total": 0, "alerts": 0},
            "updated_at": "--:--:--"
        }


def build_active_table(state: dict) -> Table:
    table = Table(
        box=box.ROUNDED,
        header_style="bold cyan",
        title="[bold cyan]● Processos ativos com score > 0[/bold cyan]",
        expand=True
    )

    table.add_column("PID",      style="dim", width=7)
    table.add_column("Processo",              width=18)
    table.add_column("Pai",      style="dim", width=18)
    table.add_column("Score",                 width=7,  justify="center")
    table.add_column("Status",                width=16)
    table.add_column("Regras",                width=40)

    for proc in state.get("processes", [])[:8]:
        classification = proc.get("classification", "BENIGN")
        style = COLOR_MAP.get(classification, "white")

        rules_text = ", ".join(
            f"{r['rule']}(+{r['weight']})"
            for r in proc.get("triggered_rules", [])
        )

        table.add_row(
            str(proc["pid"]),
            proc["name"],
            proc.get("parent_name", ""),
            str(proc["score"]),
            Text(classification, style=style),
            rules_text,
        )

    return table


def build_incident_detail(incident: dict) -> Panel:
    """
    Constrói o painel didático de um incidente.
    """
    classification = incident.get("classification", "BENIGN")
    color = COLOR_MAP.get(classification, "white")
    rules = incident.get("triggered_rules", [])

    lines = []

    # Cabeçalho do incidente
    lines.append(
        f"[{color}]{incident['name']}[/{color}]  "
        f"PID [dim]{incident['pid']}[/dim]  "
        f"Pai [dim]{incident.get('parent_name', '?')}[/dim]  "
        f"Score [{color}]{incident['score']}[/{color}]  "
        f"[{color}]{classification}[/{color}]"
    )
    lines.append(f"[dim]CMD: {incident.get('command_line', '')[:80]}[/dim]")
    lines.append("")

    for rule in rules:
        mitre = rule.get("mitre", "")
        mitre_tag = f"  [{MITRE_COLOR}][{mitre}][/{MITRE_COLOR}]" if mitre else ""

        # Nome da regra e peso
        lines.append(
            f"[bold]▶ {rule['rule']}[/bold]  "
            f"[dim]+{rule['weight']} pontos[/dim]"
            f"{mitre_tag}"
        )

        # O que foi detectado
        lines.append(f"  [dim]Detectado:[/dim] {rule.get('reason', '')}")

        # O que o processo está fazendo
        behavior = rule.get("behavior", "")
        if behavior:
            lines.append(f"")
            lines.append(f"  [cyan]O que está acontecendo:[/cyan]")
            # Quebra o texto em linhas de 80 chars para ficar legível
            for chunk in _wrap(behavior, 78):
                lines.append(f"  {chunk}")

        # Contexto ofensivo
        offensive = rule.get("offensive_context", "")
        if offensive:
            lines.append(f"")
            lines.append(f"  [yellow]Na prática ofensiva:[/yellow]")
            for chunk in _wrap(offensive, 78):
                lines.append(f"  {chunk}")

        lines.append("")

    return Panel(
        "\n".join(lines),
        title=f"[dim]{incident.get('detected_at', '--')}[/dim]",
        border_style=color.replace("bold ", ""),
        expand=True
    )


def _wrap(text: str, width: int) -> list:
    """Quebra texto em linhas respeitando o limite de largura."""
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current += ("" if not current else " ") + word
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def build_layout(state: dict) -> Layout:
    counter = state.get("event_counter", {})
    updated = state.get("updated_at", "--")
    incidents = state.get("incidents", [])

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="active", size=12),
        Layout(name="history")
    )

    layout["header"].update(Panel(
        (
            f"[cyan]Eventos capturados:[/cyan] {counter.get('total', 0)}   "
            f"[yellow]Incidentes detectados:[/yellow] {counter.get('alerts', 0)}   "
            f"[dim]Atualizado: {updated}[/dim]"
        ),
        title="[bold]Leviathan DNA — Behavioral Fingerprinting Engine[/bold]",
        border_style="blue"
    ))

    layout["active"].update(build_active_table(state))

    # Painel de histórico com detalhes didáticos
    if not incidents:
        layout["history"].update(Panel(
            "[dim]Nenhum incidente detectado ainda.[/dim]",
            title="[bold yellow]⚑ Histórico de incidentes[/bold yellow]",
            border_style="yellow"
        ))
    else:
        # Mostra os 3 incidentes mais recentes com painel completo
        panels = [build_incident_detail(inc) for inc in incidents[:3]]

        layout["history"].update(Panel(
            Columns(panels, expand=True),
            title="[bold yellow]⚑ Histórico de incidentes — detalhes[/bold yellow]",
            border_style="yellow"
        ))

    return layout


if __name__ == "__main__":
    with Live(console=console, refresh_per_second=1, screen=True) as live:
        while True:
            state = read_state()
            live.update(build_layout(state))
            time.sleep(1)