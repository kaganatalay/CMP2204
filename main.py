import socket
import threading
import json
import time

BROADCAST_INTERVAL = 8  # seconds
BROADCAST_PORT = 6000
CHAT_PORT = 6001
discovered_peers = {}
log_file = "chat_log.txt"

USERNAME = input("Enter your username: ")

# Service Announcement
def broadcast_presence():
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_message = json.dumps({"username": USERNAME}).encode('utf-8')

    while True:
        broadcast_socket.sendto(broadcast_message, ('<broadcast>', BROADCAST_PORT))
        time.sleep(BROADCAST_INTERVAL)

# Peer Discovery
def listen_for_peers():
    discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    discovery_socket.bind(('', BROADCAST_PORT))

    while True:
        message, addr = discovery_socket.recvfrom(1024)
        peer_info = json.loads(message.decode('utf-8'))
        peer_ip = addr[0]
        peer_info['timestamp'] = time.time()
        discovered_peers[peer_ip] = peer_info
        print(f"{peer_info['username']} is online")

# Chat Initiation
def view_users():
    current_time = time.time()
    print("Available users:")
    for peer_ip, peer_info in discovered_peers.items():
        if current_time - peer_info['timestamp'] <= 900:
            status = "Online" if current_time - peer_info['timestamp'] <= 10 else "Away"
            print(f"{peer_info['username']} ({status})")

def initiate_chat(username):
    peer_ip = None
    for ip, info in discovered_peers.items():
        if info['username'] == username:
            peer_ip = ip
            break
    if peer_ip:
        chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            chat_socket.connect((peer_ip, CHAT_PORT))
            message = input("Enter your message: ")
            chat_message = json.dumps({"unencryptedmessage": message}).encode('utf-8')
            chat_socket.sendall(chat_message)
            chat_socket.close()
            log_message("SENT", username, peer_ip, message)
        except:
            print("Connection could not be established.")
    else:
        print("User not found.")

def log_message(direction, username, ip, message):
    with open(log_file, 'a') as f:
        f.write(f"{time.ctime()} - {direction} - {username} ({ip}): {message}\n")

def view_chat_history():
    try:
        with open(log_file, 'r') as f:
            history = f.read()
            print("Chat History:")
            print(history)
    except FileNotFoundError:
        print("No chat history found.")

# Chat Responder
def handle_client(client_socket):
    message = client_socket.recv(1024)
    message_data = json.loads(message.decode('utf-8'))
    if 'unencryptedmessage' in message_data:
        print(f"Received message: {message_data['unencryptedmessage']}")
        log_message("RECEIVED", client_socket.getpeername()[0], message_data['unencryptedmessage'])
    client_socket.close()

def start_chat_responder():
    chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chat_socket.bind(('', CHAT_PORT))
    chat_socket.listen(5)
    print("Chat responder listening on port 6001...")

    while True:
        client_socket, addr = chat_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

# Main function
if __name__ == "__main__":
    threading.Thread(target=broadcast_presence).start()
    threading.Thread(target=listen_for_peers).start()
    threading.Thread(target=start_chat_responder).start()

    while True:
        action = input("Enter 'Users' to view online users, 'Chat' to initiate a chat, or 'History' to view chat history: ")
        if action.lower() == "users":
            view_users()
        elif action.lower() == "chat":
            username = input("Enter the username to chat with: ")
            initiate_chat(username)
        elif action.lower() == "history":
            view_chat_history()
