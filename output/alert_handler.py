from engine.process_context import ProcessContext
import json
from datetime import datetime
from collections import deque

event_counter = {"total": 0, "alerts": 0}
DISPLAY_THRESHOLD = 30

# Histórico de incidentes — persiste durante toda a sessão
# Chave: pid, valor: dict com os dados do incidente
incident_history: dict[int, dict] = {}


def handle_alert(ctx: ProcessContext):
    event_counter["total"] += 1

    if ctx.score < DISPLAY_THRESHOLD:
        return

    # Registra o incidente apenas uma vez por PID
    if ctx.pid not in incident_history:
        event_counter["alerts"] += 1

        incident = {
            "pid": ctx.pid,
            "name": ctx.name,
            "parent_name": ctx.parent_name,
            "score": ctx.score,
            "classification": ctx.classification(),
            "command_line": ctx.command_line,
            "triggered_rules": ctx.triggered_rules,
            "detected_at": ctx.detected_at.strftime("%H:%M:%S") if ctx.detected_at else datetime.now().strftime("%H:%M:%S")
        }

        incident_history[ctx.pid] = incident

        # Persiste em disco
        with open("leviathan_alerts.json", "a") as f:
            f.write(json.dumps({
                **incident,
                "timestamp": datetime.now().isoformat()
            }) + "\n")

    else:
        # Atualiza score e regras se o incidente evoluiu
        existing = incident_history[ctx.pid]
        if ctx.score > existing["score"]:
            existing["score"] = ctx.score
            existing["classification"] = ctx.classification()
            existing["triggered_rules"] = ctx.triggered_rules