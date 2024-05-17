import socket
import threading
import time
import json
from datetime import datetime, timedelta

# Configuration
BROADCAST_IP = '255.255.255.255'
BROADCAST_PORT = 6000
TCP_PORT = 6001
USERNAME = input("Enter your username: ")

# Global state
peers = {}
state_lock = threading.Lock()

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
            if ip not in peers or (ip in peers and peers[ip]['timestamp'] < current_time - timedelta(seconds=10)):
                peers[ip] = {'username': username, 'timestamp': current_time}
                print(f"{username} is online")
            else:
                peers[ip]['timestamp'] = current_time

def display_user_state():
    while True:
        time.sleep(1)
        with state_lock:
            current_time = datetime.now()
            for ip, info in list(peers.items()):
                if current_time - info['timestamp'] > timedelta(seconds=10):
                    print(f"{info['username']} is away")
                    del peers[ip]
                elif current_time - info['timestamp'] <= timedelta(seconds=10):
                    print(f"{info['username']} is online")

def handle_client_connection(client_socket, address):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        message = json.loads(data.decode())
        if "unencrypted message" in message:
            print(f"{message['username']}: {message['unencrypted message']}")

    client_socket.close()

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', TCP_PORT))
    server_socket.listen(5)
    
    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket, address)).start()

def initiate_chat():
    while True:
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
            client_socket.close()
        else:
            print("User not found or offline")

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', BROADCAST_PORT))
    
    threading.Thread(target=broadcast_presence).start()
    threading.Thread(target=listen_for_peers).start()
    threading.Thread(target=display_user_state).start()
    threading.Thread(target=start_tcp_server).start()
    
    initiate_chat()
