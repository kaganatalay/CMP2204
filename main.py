import socket
import threading
import time
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# Configuration
BROADCAST_IP = '192.168.1.255'  # Or your actual broadcast IP
BROADCAST_PORT = 6000
TCP_PORT = 6001
USERNAME = input("Enter your username: ")

# Global state
peers = {}
state_lock = threading.Lock()
chat_history = []
shared_keys = {}

# Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

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

    # Diffie-Hellman Key Exchange
    peer_public_key_bytes = client_socket.recv(1024)
    peer_public_key = dh.DHPublicKey.from_encoded_point(parameters, peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    shared_keys[ip] = shared_key

    # Key Derivation Function (KDF) to get a usable key for Fernet
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat_encryption',
    ).derive(shared_key)

    f = Fernet(derived_key)

    # Send your public key
    client_socket.sendall(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )) 

    while True:
        data = client_socket.recv(1024)
        if not data:
            break

        message = json.loads(data.decode())
        decrypted_message = f.decrypt(message['encrypted_message'].encode()).decode()
        print(f"\n- {username}: {decrypted_message}\n")
        chat_history.append((datetime.now(), username, ip, 'RECEIVED', decrypted_message))

    client_socket.close()

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', TCP_PORT))
    server_socket.listen(5)

    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket, address)).start()
    server_socket.close()  # Add the server socket close after the loop

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

        # Diffie-Hellman key exchange (client-side)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((recipient_ip, TCP_PORT))
        client_socket.sendall(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        peer_public_key_bytes = client_socket.recv(1024)
        peer_public_key = dh.DHPublicKey.from_encoded_point(parameters, peer_public_key_bytes)
        shared_key = private_key.exchange(peer_public_key)
        shared_keys[recipient_ip] = shared_key

        # Key Derivation Function (KDF) to get a usable key for Fernet
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chat_encryption',
        ).derive(shared_key)

        f = Fernet(derived_key)

        while True:
            message = input(f"\nEnter your message for {chat_username}: ")
            if not message:
                break

            encrypted_message = f.encrypt(message.encode()).decode()
            client_socket.send(json.dumps({"username": USERNAME, "encrypted_message": encrypted_message}).encode())
            chat_history.append((datetime.now(), chat_username, recipient_ip, 'SENT', message))

            client_socket.close()  # Close immediately after sending
            break 
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