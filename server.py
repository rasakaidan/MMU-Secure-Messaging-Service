import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

SERVER = "10.0.2.15"
PORT = 12345
BUFFER_SIZE = 1024
clients = []

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def handle_client(client_socket, addr):
    global clients
    print(f"[*] New connection from {addr}")
    clients.append((client_socket, None))  # Add client with no symmetric cipher yet

    try:
        pem_public_key = client_socket.recv(BUFFER_SIZE)
        client_public_key = load_pem_public_key(pem_public_key, default_backend())

        symmetric_key = generate_symmetric_key()
        encrypted_symmetric_key = encrypt_message(client_public_key, symmetric_key)
        client_socket.send(encrypted_symmetric_key)

        client_cipher = Fernet(symmetric_key)
        clients[-1] = (client_socket, client_cipher)  # Update client with cipher

        while True:
            msg = client_socket.recv(BUFFER_SIZE)
            if not msg:
                break
            decrypted_msg = client_cipher.decrypt(msg)
            broadcast_message(client_socket, decrypted_msg)

    finally:
        clients.remove((client_socket, client_cipher))
        client_socket.close()
        print(f"[*] Connection closed from {addr}")

def broadcast_message(sender, message):
    global clients
    sender_addr = sender.getpeername()
    for client_socket, client_cipher in clients:
        if client_socket != sender:
            msg_to_send = f"{sender_addr}: {message.decode('utf-8')}".encode('utf-8')
            encrypted_msg = client_cipher.encrypt(msg_to_send)
            client_socket.send(encrypted_msg)


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
