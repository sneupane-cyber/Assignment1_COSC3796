import socket
import threading

clients = {}
public_keys = {}

def handle_client(conn, addr):
    name = conn.recv(1024).decode()
    clients[name] = conn
    print(f"[SERVER] {name} connected from {addr}")

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            parts = data.decode().split(":", 2)
            cmd = parts[0]

            if cmd == "PUBKEY":
                public_key = parts[1]
                public_keys[name] = public_key
                print(f"[SERVER] Stored public key for {name}")

            elif cmd == "GETKEY":
                target = parts[1]
                if target in public_keys:
                    conn.send(f"PUBKEY:{target}:{public_keys[target]}".encode())
                else:
                    conn.send(f"ERROR:{target} not found".encode())

            elif cmd == "TO":
                receiver = parts[1]
                msg = parts[2]
                if receiver in clients:
                    clients[receiver].send(f"MSG:{name}:{msg}".encode())
                    print(f"[SERVER] Forwarded message from {name} to {receiver}")
                else:
                    print(f"[SERVER] Receiver {receiver} not found")

        except Exception as e:
            print("[SERVER] Error:", e)
            break

    print(f"[SERVER] {name} disconnected")
    conn.close()
    clients.pop(name, None)
    public_keys.pop(name, None)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5000))
    server.listen()
    print("[SERVER] Running on port 5000...")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    start_server()
