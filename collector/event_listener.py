import win32evtlog
import win32con
import xml.etree.ElementTree as ET
from typing import Callable

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Namespace do XML dos eventos do Sysmon
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def parse_event(event_handle) -> dict:
    """
    Recebe um handle de evento e retorna um dicionário
    com os campos relevantes já extraídos.
    """
    xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
    root = ET.fromstring(xml_str)

    # Extrai o Event ID
    event_id = int(root.find(f"{NS}System/{NS}EventID").text)

    # Extrai todos os campos de EventData como dicionário
    event_data = {}
    event_data_node = root.find(f"{NS}EventData")
    if event_data_node is not None:
        for data in event_data_node.findall(f"{NS}Data"):
            name = data.get("Name")
            value = data.text or ""
            event_data[name] = value

    return {
        "event_id": event_id,
        "data": event_data
    }


def start_listener(on_event: Callable[[dict], None]):
    """
    Abre subscrição no canal do Sysmon e chama on_event()
    para cada evento novo que chegar.
    Roda indefinidamente até Ctrl+C.
    """
    print(f"[*] Iniciando listener no canal: {SYSMON_CHANNEL}")

    callback_handle = None

    def raw_callback(action, context, event_handle):
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                parsed = parse_event(event_handle)
                on_event(parsed)
            except Exception as e:
                print(f"[ERRO] Falha ao processar evento: {e}")

    callback_handle = win32evtlog.EvtSubscribe(
        SYSMON_CHANNEL,
        win32evtlog.EvtSubscribeToFutureEvents,
        Callback=raw_callback
    )

    print("[*] Listener ativo. Aguardando eventos...\n")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Listener encerrado.")