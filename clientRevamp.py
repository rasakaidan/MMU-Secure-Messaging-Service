import tkinter as tk
import socket
import threading

class MessagingApp:

    def __init__(self, master):
        self.master = master
        self.master.title("Chronos")

        self.entry = tk.Entry(self.master)
        self.entry.pack()

        self.button = tk.Button(self.master, text="Send", command=self.send_message)
        self.button.pack()

        self.text = tk.Text(self.master)
        self.text.pack()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # would chasnge localhost if we host server online, port number has to be same as server.
        self.sock.connect(('localhost', 12345))

        self.thread = threading.Thread(target=self.receive_messages)
        self.thread.daemon = True
        self.thread.start()

    def receive_messages(self):
        # Receive messages from the server and update the text area
        while True:
            data = self.sock.recv(1024).decode()
            if not data:
                break
            # need to add a newline here after message - still not sure how textbox works
            self.text.insert(tk.END, data)

    def receive_messages(self):
        while True:
            msg = client_socket.recv(BUFFER_SIZE)
            if not msg:
                break
            decrypted_msg = symmetric_cipher.decrypt(msg)
            self.text.insert(tk.END, decrypted_msg.decode('utf-8') + "\n")

    # set message val to entrybox, encode then clear 
    def send_message(self):
        message = self.entry.get()
        self.sock.sendall(message.encode())
        self.entry.delete(0, tk.END)

root = tk.Tk()
app = MessagingApp(root)
root.mainloop()