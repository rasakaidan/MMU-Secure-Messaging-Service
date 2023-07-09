import socket
import threading
import tkinter as tk
import queue
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
    global client_socket, symmetric_cipher, message_queue
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Attempting to connect to server...")
    client_socket.connect((SERVER, PORT))
    print("Connected to server.")

    private_key, public_key = generate_key_pair()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_socket.send(pem_public_key)

    encrypted_symmetric_key = client_socket.recv(BUFFER_SIZE)
    symmetric_key = decrypt_message(private_key, encrypted_symmetric_key)
    symmetric_cipher = Fernet(symmetric_key)

    message_queue.put("Connected")

    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()

def receive_messages():
    global client_socket, symmetric_cipher, chat_history
    while True:
        msg = client_socket.recv(BUFFER_SIZE)
        if not msg:
            break
        decrypted_msg = symmetric_cipher.decrypt(msg)

        chat_history.config(state=tk.NORMAL)
        chat_history.insert(tk.END, decrypted_msg.decode('utf-8') + "\n")
        chat_history.config(state=tk.DISABLED)


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

def update_gui():
    global message_queue, chat_history, send_button, status_label
    try:
        msg = message_queue.get_nowait()
        if msg == "Connected":
            send_button.config(state=tk.NORMAL)
            status_label.config(text="Connected")
        else:
            chat_history.config(state=tk.NORMAL)
            chat_history.insert(tk.END, msg)
            chat_history.config(state=tk.DISABLED)
    except queue.Empty:
        pass
    finally:
        root.after(100, update_gui)


def create_gui():
    global root, chat_history, input_field, send_button, status_label, message_queue

    message_queue = queue.Queue()

    root = tk.Tk()
    root.title("Secure Chat")

    chat_frame = tk.Frame(root)
    scrollbar = tk.Scrollbar(chat_frame)
    chat_history = tk.Text(chat_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, fg="black")
    chat_history.config(state=tk.DISABLED)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    chat_history.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    chat_frame.pack(fill=tk.BOTH, expand=True)

    input_frame = tk.Frame(root)
    input_field = tk.Entry(input_frame)
    input_field.pack(side=tk.LEFT, fill=tk.X, expand=True)
    send_button = tk.Button(input_frame, text="Send", command=send_message, state=tk.DISABLED)
    send_button.pack(side=tk.RIGHT)
    status_label = tk.Label(input_frame, text="Connecting...")
    status_label.pack(side=tk.RIGHT)
    input_frame.pack(fill=tk.X)

    root.after(100, connect_to_server)
    root.after(100, update_gui)

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    create_gui()





