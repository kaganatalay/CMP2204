import socket
import threading
import time
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from diffiehellman.diffiehellman import DiffieHellman

# Configuration
BROADCAST_IP = '192.168.1.255'  # Or your actual broadcast IP
BROADCAST_PORT = 6000
TCP_PORT = 6001
USERNAME = input("Enter your username: ")

# Global state
peers = {}
state_lock = threading.Lock()
chat_history = []

# Diffie-Hellman for secure chat
dh_objects = {}  # Store Diffie-Hellman objects per peer

def broadcast_presence():
    while True:
        message = json.dumps({"username": USERNAME, "ip": socket.gethostbyname(socket.gethostname())})
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
                print(f"\n{username} is online\n")
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
                    print(f"\n{info['username']} is away\n")
                elif last_seen <= timedelta(seconds=10) and info['state'] != 'online':
                    info['state'] = 'online'
                    print(f"\n{info['username']} is online\n")

def handle_client_connection(client_socket, address):
    username = peers[address[0]]['username']
    dh = dh_objects.get(username)  # Get existing DH object or create a new one

    while True:
        data = client_socket.recv(1024)
        if not data:
            break

        message = json.loads(data.decode())

        if "key" in message:
            if not dh:
                dh = DiffieHellman()
                dh_objects[username] = dh
                public_key = dh.gen_public_key()
                client_socket.send(json.dumps({"key": public_key}).encode())
            shared_key = dh.gen_shared_key(message['key'])
            encryption_key = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt_',
                iterations=390000,
            ).derive(str(shared_key).encode())
        elif "encrypted_message" in message:
            f = Fernet(base64.urlsafe_b64encode(encryption_key))
            decrypted_message = f.decrypt(message["encrypted_message"].encode()).decode()
            print(f"\n- {username}: {decrypted_message}\n")
            chat_history.append((datetime.now(), username, address[0], 'RECEIVED', decrypted_message))
        elif "unencrypted_message" in message:
            print(f"\n- {username}: {message['unencrypted_message']}\n")
            chat_history.append((datetime.now(), username, address[0], 'RECEIVED', message['unencrypted_message']))

    client_socket.close()

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', TCP_PORT))
    server_socket.listen(5)
    
    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket, address)).start()
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
        is_secure = input("Chat securely? (yes/no): ").lower() == "yes"
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((recipient_ip, TCP_PORT))

        if is_secure:
            dh = DiffieHellman()
            dh_objects[chat_username] = dh
            public_key = dh.gen_public_key()
            client_socket.send(json.dumps({"key": public_key}).encode())
            data = client_socket.recv(1024)
            if data:
                message = json.loads(data.decode())
                if "key" in message:
                    shared_key = dh.gen_shared_key(message['key'])
                    encryption_key = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=b'salt_',
                        iterations=390000,
                    ).derive(str(shared_key).encode())

        while True:
            message = input(f"\nEnter your message for {chat_username}: ")
            if not message:
                break
            if is_secure:
                f = Fernet(base64.urlsafe_b64encode(encryption_key))
                encrypted_message = f.encrypt(message.encode()).decode()
                client_socket.send(json.dumps({"encrypted_message": encrypted_message}).encode())
            else:
                client_socket.send(json.dumps({"username": USERNAME, "unencrypted_message": message}).encode())
            chat_history.append((datetime.now(), chat_username, recipient_ip, 'SENT', message))
        client_socket.close()
    else:
        print("\nUser not found or offline\n")

def menu():
    while True:
        print("\nMenu:")
        print("1. View online users")
        print("2. Initiate chat")
        print("3. View chat history")
        choice = input("Enter your choice: ")

        if choice == '1':
            view_online_users()
        elif choice == '2':
            initiate_chat()
        elif choice == '3':
            view_chat_history()
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
