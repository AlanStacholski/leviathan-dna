from collector.event_listener import start_listener

def handle(event):
    print(f"Event ID: {event['event_id']} | Data: {event['data']}")

start_listener(handle)