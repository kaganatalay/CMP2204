import socket
import threading
import time
import json
from datetime import datetime, timedelta

# Configuration
BROADCAST_IP = '192.168.1.255'
BROADCAST_PORT = 6000
TCP_PORT = 6001
USERNAME = input("Enter your username: ")

# Global state
peers = {}
state_lock = threading.Lock()
chat_history = []

def broadcast_presence():
    while True:
        message = json.dumps({"username": USERNAME})
        sock.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
        time.sleep(8)

def listen_for_peers():
    while True:
        data, addr = sock.recvfrom(1024)
        message = json.loads(data.decode())
        username = message["username"]
        ip = addr[0]
        
        with state_lock:
            current_time = datetime.now()
            if ip not in peers:
                peers[ip] = {'username': username, 'timestamp': current_time, 'state': 'online'}
                print(f"{username} is online")
            else:
                peers[ip]['timestamp'] = current_time

def display_user_state():
    while True:
        time.sleep(1)
        with state_lock:
            current_time = datetime.now()
            for ip, info in list(peers.items()):
                last_seen = current_time - info['timestamp']
                if last_seen > timedelta(seconds=10) and info['state'] != 'away':
                    info['state'] = 'away'
                    print(f"{info['username']} is away")
                elif last_seen <= timedelta(seconds=10) and info['state'] != 'online':
                    info['state'] = 'online'
                    print(f"{info['username']} is online")

def handle_client_connection(client_socket, address):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        message = json.loads(data.decode())
        if "unencrypted message" in message:
            print(f"{message['username']}: {message['unencrypted message']}")
            chat_history.append((datetime.now(), message['username'], address[0], 'RECEIVED', message['unencrypted message']))
        elif "encrypted message" in message:
            # Handle encrypted message if needed
            pass

    client_socket.close()

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', TCP_PORT))
    server_socket.listen(5)
    
    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket, address)).start()

def view_online_users():
    with state_lock:
        current_time = datetime.now()
        for ip, info in peers.items():
            last_seen = current_time - info['timestamp']
            state = "Online" if last_seen <= timedelta(seconds=10) else "Away"
            print(f"{info['username']} ({state})")

def view_chat_history():
    for entry in chat_history:
        timestamp, username, ip, direction, message = entry
        print(f"[{timestamp}] {username} ({ip}) {direction}: {message}")

def initiate_chat():
    chat_username = input("Enter the username to chat with: ")
    recipient_ip = None
    
    with state_lock:
        for ip, info in peers.items():
            if info['username'] == chat_username:
                recipient_ip = ip
                break
    
    if recipient_ip:
        message = input("Enter your message: ")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((recipient_ip, TCP_PORT))
        client_socket.send(json.dumps({"username": USERNAME, "unencrypted message": message}).encode())
        chat_history.append((datetime.now(), chat_username, recipient_ip, 'SENT', message))
        client_socket.close()
    else:
        print("User not found or offline")

def menu():
    while True:
        print("\nMenu:")
        print("1. View online users")
        print("2. Initiate chat")
        print("3. View chat history")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            view_online_users()
        elif choice == '2':
            initiate_chat()
        elif choice == '3':
            view_chat_history()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', BROADCAST_PORT))
    
    threading.Thread(target=broadcast_presence).start()
    threading.Thread(target=listen_for_peers).start()
    threading.Thread(target=display_user_state).start()
    threading.Thread(target=start_tcp_server).start()
    
    menu()
