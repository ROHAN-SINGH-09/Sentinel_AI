import os

def alert_user(message):
    print(f"[ALERT]: {message}")

def block_ip(ip):
    print(f"[ACTION] Blocking IP: {ip}")

    # Windows firewall block command
    command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
    
    try:
        os.system(command)
    except Exception as e:
        print("Block Error:", e)
        def alert_user(message):
           print(f"[ALERT]: {message}")
           def alert_user(msg):
              print(f"[ALERT]: {msg}")