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
terminate = False

def broadcast_presence():
    global terminate
    while not terminate:
        message = json.dumps({"username": USERNAME})
        sock.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
        time.sleep(8)
    sock.close()

def listen_for_peers():
    global terminate
    while not terminate:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.error:
            break
        message = json.loads(data.decode())
        username = message["username"]
        ip = addr[0]
        
        with state_lock:
            current_time = datetime.now()
            if ip not in peers:
                peers[ip] = {'username': username, 'timestamp': current_time, 'state': 'online'}
                print(f"\n{username} is online\n")
            else:
                peers[ip]['timestamp'] = current_time
    sock.close()

def display_user_state():
    global terminate
    while not terminate:
        time.sleep(1)
        with state_lock:
            current_time = datetime.now()
            for ip, info in list(peers.items()):
                last_seen = current_time - info['timestamp']
                if last_seen > timedelta(seconds=10) and info['state'] != 'away':
                    info['state'] = 'away'
                    print(f"\n{info['username']} is away\n")
                elif last_seen <= timedelta(seconds=10) and info['state'] != 'online':
                    info['state'] = 'online'
                    print(f"\n{info['username']} is online\n")

def handle_client_connection(client_socket, address):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        message = json.loads(data.decode())
        if "unencrypted message" in message:
            print(f"\n{message['username']}: {message['unencrypted message']}\n")
            chat_history.append((datetime.now(), message['username'], address[0], 'RECEIVED', message['unencrypted message']))
        elif "encrypted message" in message:
            # Handle encrypted message if needed
            pass
    client_socket.close()

def start_tcp_server():
    global terminate
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', TCP_PORT))
    server_socket.listen(5)
    
    while not terminate:
        try:
            client_socket, address = server_socket.accept()
            threading.Thread(target=handle_client_connection, args=(client_socket, address)).start()
        except socket.error:
            break
    server_socket.close()

def view_online_users():
    with state_lock:
        current_time = datetime.now()
        print("\nOnline Users:\n")
        for ip, info in peers.items():
            last_seen = current_time - info['timestamp']
            state = "Online" if last_seen <= timedelta(seconds=10) else "Away"
            print(f"{info['username']} ({state})")
        print()

def view_chat_history():
    print("\nChat History:\n")
    for entry in chat_history:
        timestamp, username, ip, direction, message = entry
        print(f"[{timestamp}] {username} ({ip}) {direction}: {message}")
    print()

def initiate_chat():
    chat_username = input("\nEnter the username to chat with: ")
    recipient_ip = None
    
    with state_lock:
        for ip, info in peers.items():
            if info['username'] == chat_username:
                recipient_ip = ip
                break
    
    if recipient_ip:
        message = input(f"\nEnter your message for {chat_username}: ")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((recipient_ip, TCP_PORT))
        client_socket.send(json.dumps({"username": USERNAME, "unencrypted message": message}).encode())
        chat_history.append((datetime.now(), chat_username, recipient_ip, 'SENT', message))
        client_socket.close()
    else:
        print("\nUser not found or offline\n")

def menu():
    global terminate
    while True:
        print("\nMenu:")
        print("1. View online users")
        print("2. Initiate chat")
        print("3. View chat history")
        print("4. Exit")
        choice = input("\nEnter your choice: ")

        if choice == '1':
            view_online_users()
        elif choice == '2':
            initiate_chat()
        elif choice == '3':
            view_chat_history()
        elif choice == '4':
            terminate = True
            break
        else:
            print("\nInvalid choice. Please try again.\n")

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', BROADCAST_PORT))
    
    threading.Thread(target=broadcast_presence).start()
    threading.Thread(target=listen_for_peers).start()
    threading.Thread(target=display_user_state).start()
    threading.Thread(target=start_tcp_server).start()
    
    menu()
    print("\nExiting... Please wait for background threads to finish.\n")
    time.sleep(2)  # Give threads time to clean up
