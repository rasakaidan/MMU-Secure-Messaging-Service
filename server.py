import socket
import threading

SERVER = "127.0.0.1"
PORT = 12345
BUFFER_SIZE = 1024
clients = []

def handle_client(client_socket, addr):
    global clients
    print(f"[*] New connection from {addr}")
    clients.append(client_socket)

    try:
        while True:
            msg = client_socket.recv(BUFFER_SIZE)
            if not msg:
                break
            broadcast_message(client_socket, msg)
    finally:
        clients.remove(client_socket)
        client_socket.close()
        print(f"[*] Connection closed from {addr}")

def broadcast_message(sender, message):
    global clients
    for client in clients:
        if client != sender:
            client.send(message)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER, PORT))
    server_socket.listen(5)
    print(f"[*] Listening on {SERVER}:{PORT}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.start()
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()