import socket
import threading
import json
import os
import time
from datetime import datetime

# Constants
BROADCAST_IP = '192.168.169.255'
BROADCAST_PORT = 6000
TCP_PORT = 6001
DISCOVERY_INTERVAL = 8
USER_TIMEOUT = 900
ONLINE_TIMEOUT = 10
LOG_FILENAME = 'chat_history.log'

# Global dictionary to store peer information
peers = {}

# Lock for thread-safe operations on peers dictionary
lock = threading.Lock()

# Function to broadcast presence
def broadcast_presence(username):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        message = json.dumps({'username': username})
        udp_socket.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
        time.sleep(DISCOVERY_INTERVAL)

# Function to listen for broadcasts
def listen_for_broadcasts():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('', BROADCAST_PORT))
    while True:
        message, addr = udp_socket.recvfrom(1024)
        ip = addr[0]
        data = json.loads(message.decode())
        username = data['username']
        with lock:
            peers[ip] = {'username': username, 'timestamp': time.time()}
            # print(f"{username} is online")

# Function to display peers
def display_peers():
    current_time = time.time()
    with lock:
        for ip, info in peers.items():
            if current_time - info['timestamp'] <= USER_TIMEOUT:
                status = "(Online)" if current_time - info['timestamp'] <= ONLINE_TIMEOUT else "(Away)"
                print(f"{info['username']} {status}")

# Function to initiate chat
def initiate_chat():
    peer_name = input("Enter the username to chat with: ")
    with lock:
        peer_ip = next((ip for ip, info in peers.items() if info['username'] == peer_name), None)
    if peer_ip is None:
        print("User not found.")
        return
    
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((peer_ip, TCP_PORT))
    
    while True:
        message = input("Enter your message (type 'exit' to end chat): ")
        if message.lower() == 'exit':
            break
        tcp_socket.send(message.encode())
        log_message(peer_name, message, 'SENT')
    
    tcp_socket.close()

# Function to handle incoming TCP connections
def handle_connection(conn, addr):
    while True:
        message = conn.recv(1024).decode()
        if not message:
            break
        username = peers.get(addr[0], {}).get('username', 'Unknown')
        print(f"Message from {username}: {message}")
        log_message(username, message, 'RECEIVED')
    conn.close()

# Function to log messages
def log_message(username, message, direction):
    with open(LOG_FILENAME, 'a') as file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        file.write(f"{timestamp} | {username} | {direction} | {message}\n")

# Function to start TCP server
def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', TCP_PORT))
    server_socket.listen()
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_connection, args=(conn, addr)).start()

# Main function to run the application
def main():
    username = input("Enter your username: ")
    threading.Thread(target=broadcast_presence, args=(username,)).start()
    threading.Thread(target=listen_for_broadcasts).start()
    threading.Thread(target=start_tcp_server).start()
    while True:
        print("\n1. View Online Users\n2. Initiate Chat\n3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            display_peers()
        elif choice == '2':
            initiate_chat()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
