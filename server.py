import socket
import threading

clients = {}  # Dictionary to store client sockets and their public keys

def recv_full(sock, length):
    data = bytearray()  # Initialize a bytearray to accumulate bytes
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise Exception("Incomplete data received")
        data.extend(more)  # Append received data to the bytearray
    return bytes(data)  # Convert bytearray back to bytes before returning

# Function to send a public key to a specific client and wait for acknowledgment
def send_public_key_with_ack(client_sock, public_key):
    try:
        client_sock.send(len(public_key).to_bytes(4, byteorder='little'))
        client_sock.send(public_key)
        
        # Wait for acknowledgment
        ack = recv_full(client_sock, 12)  # Assume "KEY_RECEIVED" acknowledgment
        if ack.decode() != "KEY_RECEIVED":
            raise Exception("Acknowledgment not received")
    except Exception as e:
        print(f"Error sending public key with acknowledgment: {e}")

# Handle each client
def handle_client(client_sock, addr):
    print(f"Client connected: {addr}")
    try:
        # Receive public key from the new client
        public_key_size = int.from_bytes(client_sock.recv(4), 'little')
        print(f"Expecting public key of size {public_key_size} bytes")
        
        public_key = recv_full(client_sock, public_key_size)
        print(f"Received public key of size {public_key_size} bytes from client {addr}")

        # Store the client and its public key
        clients[client_sock] = public_key
        
        # Send the new client's public key to all other clients and vice versa
        for other_client_sock in clients:
            if other_client_sock != client_sock:
                send_public_key_with_ack(other_client_sock, public_key)
                send_public_key_with_ack(client_sock, clients[other_client_sock])

        # Start handling message relay
        while True:
            msg_size = int.from_bytes(client_sock.recv(4), 'little')
            if msg_size == 0:
                print("Received zero-length message, breaking loop.")
                break

            message = recv_full(client_sock, msg_size)
            print(f"Received message of size {msg_size} from {addr}")

            # Relay the message to all other clients
            for other_client_sock in clients:
                if other_client_sock != client_sock:
                    other_client_sock.send(msg_size.to_bytes(4, byteorder='little'))
                    other_client_sock.send(message)
                    print(f"Sent message of size {msg_size} to another client")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print(f"Client disconnected: {addr}")
        client_sock.close()
        clients.pop(client_sock, None)

def start_server():
    port = 8001
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('127.0.0.1', port))
    server_sock.listen(5)
    print(f"Server listening on 127.0.0.1:{port}")

    while True:
        client_sock, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr)).start()

if __name__ == "__main__":
    start_server()
