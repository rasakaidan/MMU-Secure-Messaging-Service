import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

SERVER = "10.0.2.15"
PORT = 12345
BUFFER_SIZE = 1024

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

def decrypt_message(private_key, message):
    plaintext = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def connect_to_server():
    global client_socket, symmetric_cipher
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER, PORT))

    private_key, public_key = generate_key_pair()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_socket.send(pem_public_key)

    encrypted_symmetric_key = client_socket.recv(BUFFER_SIZE)
    symmetric_key = decrypt_message(private_key, encrypted_symmetric_key)
    symmetric_cipher = Fernet(symmetric_key)

    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()

def receive_messages():
    global client_socket, symmetric_cipher, chat_history
    while True:
        msg = client_socket.recv(BUFFER_SIZE)
        if not msg:
            break
        decrypted_msg = symmetric_cipher.decrypt(msg)
        chat_history.insert(tk.END, decrypted_msg.decode('utf-8') + "\n")

def send_message():
    global client_socket, symmetric_cipher, input_field
    msg = input_field.get()
    input_field.delete(0, tk.END)
    encrypted_msg = symmetric_cipher.encrypt(msg.encode('utf-8'))
    client_socket.send(encrypted_msg)

def on_closing():
    global client_socket
    client_socket.close()
    root.quit()

def create_gui():
    global root, chat_history, input_field

    root = tk.Tk()
    root.title("Secure Chat")

    chat_frame = tk.Frame(root)
    scrollbar = tk.Scrollbar(chat_frame)
    chat_history = tk.Text(chat_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
    chat_history.config(state=tk.DISABLED)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    chat_history.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    chat_frame.pack(fill=tk.BOTH, expand=True)

    input_frame = tk.Frame(root)
    input_field = tk.Entry(input_frame)
    input_field.pack(side=tk.LEFT, fill=tk.X, expand=True)
    send_button = tk.Button(input_frame, text="Send", command=send_message)
    send_button.pack(side=tk.RIGHT)
    input_frame.pack(fill=tk.X)

    connect_to_server()

if __name__ == "__main__":
    create_gui()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

     