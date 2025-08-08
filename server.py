import socket
import threading


def start_udp_listener():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    server_address = ('', 8888)
    sock.bind(server_address)

    print("UDP listener started on port 8888")

    while True:
        data, address = sock.recvfrom(4096)
        print(f"Received {len(data)} bytes from {address}")
        print(data.decode())
        data = "Hi SecureNet!".encode()
        if data:
            sent = sock.sendto(data, address)
            print(f"Sent {sent} bytes back to {address}")


def handle_client(connection, client_address):
    print(f"New thread: Handling connection from {client_address}")
    try:
        while True:
            data = connection.recv(4096)
            if data:
                print(f"Received {len(data)} bytes from {client_address}")
                print(data.decode())
                connection.sendall("Hi SecureNet!".encode())
            else:
                break
    finally:
        print(f"Closing connection with {client_address}")
        connection.close()


def start_tcp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = ('', 8888)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen()
    print("TCP listener started on port 8888")

    while True:
        connection, client_address = sock.accept()
        thread = threading.Thread(target=handle_client, args=(connection, client_address))
        thread.daemon = True  # Optional: exits thread when main thread exits
        thread.start()


if __name__ == "__main__":
    start_tcp_listener()
