import threading
from service_announcer import ServiceAnnouncer
from peer_discovery import PeerDiscovery
from chat_initiator import ChatInitiator
from chat_responder import ChatResponder

if __name__ == "__main__":
    username = input("Enter your username: ")
    announcer = ServiceAnnouncer(username)
    discovery = PeerDiscovery()
    initiator = ChatInitiator
