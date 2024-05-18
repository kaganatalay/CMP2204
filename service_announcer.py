import socket
import time
import json

BROADCAST_PORT = 6000
BROADCAST_IP = "192.168.1.255"  # This should be updated to the correct broadcast address

class ServiceAnnouncer:
    def __init__(self, username):
        self.username = username
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    def broadcast(self):
        message = json.dumps({"username": self.username})
        while True:
            self.sock.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
            time.sleep(8)
