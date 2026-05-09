import json
import threading
import time
from datetime import datetime

STATE_FILE = "leviathan_state.json"


def serialize_table(process_table: dict) -> list:
    by_name: dict = {}

    for ctx in process_table.values():
        if ctx.score == 0:
            continue
        name = ctx.name.lower()
        if name not in by_name or ctx.score > by_name[name].score:
            by_name[name] = ctx

    result = []
    for ctx in by_name.values():
        result.append({
            "pid": ctx.pid,
            "name": ctx.name,
            "parent_name": ctx.parent_name,
            "score": ctx.score,
            "classification": ctx.classification(),
            "command_line": ctx.command_line,
            "triggered_rules": ctx.triggered_rules,
        })

    return sorted(result, key=lambda x: x["score"], reverse=True)


def start_state_writer(process_table: dict, event_counter: dict, incident_history: dict):
    def run():
        while True:
            try:
                state = {
                    "updated_at": datetime.now().strftime("%H:%M:%S"),
                    "event_counter": event_counter,
                    "processes": serialize_table(process_table),
                    "incidents": sorted(             # ← histórico completo
                        incident_history.values(),
                        key=lambda x: x["detected_at"],
                        reverse=True                 # mais recente primeiro
                    )
                }
                with open(STATE_FILE, "w") as f:
                    json.dump(state, f)
            except Exception:
                pass
            time.sleep(1)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()