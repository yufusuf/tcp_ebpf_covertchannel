import os
import socket
import time
import random
import sys


def udp_sender():
    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    message = "Hello, InSecureNet!"

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while True:
            # Send message to the server
            sock.sendto(message.encode(), (host, port))
            print(f"Message sent to {host}:{port}")

            # Receive response from the server
            response, server = sock.recvfrom(4096)
            print(f"Response from server: {response.decode()}")

            # Sleep for 1 second
            # time.sleep(0.01)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()


def tcp_sender():
    host = "10.0.0.1"
    port = 8888
    message = "Hello, InSecureNet!"
    if len(sys.argv) < 2:
        print("Usage: python sender.py <delay_lambda> in ms")
        return
    delay_lambda = float(sys.argv[1]) / 1000  # Convert ms to seconds
    print(f"Delay lambda: {delay_lambda}")

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return

    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        while True:
            # Send message to the server
            sock.sendall((message + str(sock)).encode())
            print(f"Message sent to {host}:{port}")

            # Sleep for 1 second
            # Receive response from the server
            response = sock.recv(4096)
            print(f"Response from server: {response.decode()}")

            if delay_lambda != 0:
                delay = random.expovariate(1 / delay_lambda)
                time.sleep(delay)
            # time.sleep(random.expovariate(1 / 0.002))  # Example delay of 0.01 seconds
            # time.sleep(001)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    tcp_sender()
