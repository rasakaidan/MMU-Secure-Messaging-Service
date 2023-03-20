import socket

# Set up a socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a local address and port number
sock.bind(('localhost', 9999))

# Listen for incoming connections
sock.listen(1)

# Wait for a client to connect
print('Waiting for a client to connect...')
conn, addr = sock.accept()
print('Connected by', addr)

# Receive and handle messages from the client
while True:
    data = conn.recv(1024).decode()
    if not data:
        break
    print('Received message:', data)

    # Echo the message back to the client
    conn.sendall(data.encode())

# Close the connection
conn.close()
