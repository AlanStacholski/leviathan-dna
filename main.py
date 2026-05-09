# main.py
import subprocess
from collector.event_listener import start_listener
from engine.process_context import ProcessContext
from engine.rule_engine import evaluate
from engine.whitelist import is_trusted_process, is_trusted_pid
from output.alert_handler import handle_alert, event_counter, incident_history
from output.state_writer import start_state_writer

process_table: dict[int, ProcessContext] = {}


def get_parent_name(parent_pid: int) -> str:
    parent_ctx = process_table.get(parent_pid)
    if parent_ctx:
        return parent_ctx.name
    return ""


def on_event(event: dict):
    event_id = event["event_id"]
    data = event["data"]

    if event_id == 1:
        pid = int(data.get("ProcessId", 0))
        parent_pid = int(data.get("ParentProcessId", 0))
        name = data.get("Image", "unknown").split("\\")[-1]
        cmd = data.get("CommandLine", "")

        if is_trusted_pid(pid) or is_trusted_process(name):
            return

        parent_name = get_parent_name(parent_pid)

        process_table[pid] = ProcessContext(
            pid=pid,
            name=name,
            parent_pid=parent_pid,
            parent_name=parent_name,
            command_line=cmd
        )

    pid = int(data.get("ProcessId", 0))
    if pid in process_table:
        ctx = process_table[pid]
        ctx.add_event(event)
        evaluate(ctx)
        handle_alert(ctx)


if __name__ == "__main__":
    start_state_writer(process_table, event_counter, incident_history)  # ← atualizado

    subprocess.Popen(
        ["python", "output/dashboard.py"],
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )

    print("Leviathan DNA — Engine iniciada")
    print("Dashboard aberto em janela separada")
    print("Pressione Ctrl+C para encerrar\n")

    start_listener(on_event)