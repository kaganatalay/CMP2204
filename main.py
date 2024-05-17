import socket
import threading
import time
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Configuration
BROADCAST_IP = '192.168.1.255'  # Or your actual broadcast IP
BROADCAST_PORT = 6000
TCP_PORT = 6001
USERNAME = input("Enter your username: ")

# Global state
peers = {}
state_lock = threading.Lock()
chat_history = []

# Parameters for Diffie-Hellman key exchange
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_keys = {}  # Store private keys per peer
public_keys = {}   # Store public keys per peer
shared_secrets = {}  # Store shared secrets per peer

def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def deserialize_key(key_bytes):
    return serialization.load_pem_public_key(
        key_bytes.encode('utf-8'),
        backend=default_backend()
    )

def derive_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

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
    ip = address[0]
    username = peers[ip]['username']
    private_key = private_keys.get(username)

    while True:
        data = client_socket.recv(1024)
        if not data:
            break

        message = json.loads(data.decode())

        if "public_key" in message:
            peer_public_key = deserialize_key(message["public_key"])
            if not private_key:
                private_key = parameters.generate_private_key()
                private_keys[username] = private_key
            shared_secret = private_key.exchange(peer_public_key)
            encryption_key = derive_key(shared_secret)
            shared_secrets[username] = encryption_key
            print(f"Received public key from {username} and derived shared secret")

        elif "encrypted_message" in message:
            encryption_key = shared_secrets.get(username)
            if encryption_key:
                f = Fernet(base64.urlsafe_b64encode(encryption_key))
                decrypted_message = f.decrypt(message["encrypted_message"].encode()).decode()
                print(f"\n- {username}: {decrypted_message}\n")
                chat_history.append((datetime.now(), username, ip, 'RECEIVED', decrypted_message))
            else:
                print(f"Error: No encryption key found for {username}")

        elif "unencrypted_message" in message:
            print(f"\n- {username}: {message['unencrypted_message']}\n")
            chat_history.append((datetime.now(), username, ip, 'RECEIVED', message['unencrypted_message']))

    client_socket.close()  # Close the connection after handling the message

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
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            private_keys[chat_username] = private_key
            public_keys[chat_username] = public_key
            client_socket.send(json.dumps({"public_key": serialize_key(public_key)}).encode())
            print(f"Sent public key to {chat_username}: {serialize_key(public_key)}")
            data = client_socket.recv(1024)
            if data:
                message = json.loads(data.decode())
                if "public_key" in message:
                    peer_public_key = deserialize_key(message["public_key"])
                    shared_secret = private_key.exchange(peer_public_key)
                    encryption_key = derive_key(shared_secret)
                    shared_secrets[chat_username] = encryption_key
                    print(f"Received public key from {chat_username} and derived shared secret")

        while True:
            message = input(f"\nEnter your message for {chat_username}: ")
            if not message:
                break
            if is_secure:
                encryption_key = shared_secrets.get(chat_username)
                if encryption_key:
                    f = Fernet(base64.urlsafe_b64encode(encryption_key))
                    encrypted_message = f.encrypt(message.encode()).decode()
                    client_socket.send(json.dumps({"encrypted_message": encrypted_message}).encode())
                else:
                    print(f"Error: No encryption key found for {chat_username}")
            else:
                client_socket.send(json.dumps({"username": USERNAME, "unencrypted_message": message}).encode())
            chat_history.append((datetime.now(), chat_username, recipient_ip, 'SENT', message))
            client_socket.close()  # Close immediately after sending
            break  # Exit the loop after sending one message
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
