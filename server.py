import socket
import threading

host = 'localhost'
port = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host, port))
sock.listen()
clients = []


def broadcast(message):
    for client in clients:
        client.send(message)


def handle_client(client):
    while True:
        try:
            #test to see if over 1024 bytes triggers except clause
            message = client.recv(1024)
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            broadcast(f'A User has left the chat room!'.encode('utf-8'))
            break

def receive():
    while True:
        print('Server is running and listening ...')
        client, address = sock.accept()
        print(f'connection is established with {str(address)}')
        clients.append(client)
        broadcast(f'User has connected to the chat room'.encode('utf-8'))
        client.send(' you are now connected!'.encode('utf-8'))
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()


if __name__ == "__main__":
    receive()
