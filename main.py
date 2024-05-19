import threading
from service_announcer import ServiceAnnouncer
from peer_discovery import PeerDiscovery
from chat_initiator import ChatInitiator
from chat_responder import ChatResponder

if __name__ == "__main__":
    username = input("Enter your username: ")
    announcer = ServiceAnnouncer(username)
    discovery = PeerDiscovery()
    initiator = ChatInitiator(discovery)
    responder = ChatResponder(discovery)  # Pass the peer_discovery object here

    threading.Thread(target=announcer.broadcast).start()
    threading.Thread(target=discovery.listen).start()
    threading.Thread(target=responder.listen).start()

    while True:
        command = input("Enter 'Users' to view online users, 'Chat' to start a chat, 'History' to view chat history: ").lower()
        if command == "users":
            for ip, (username, status) in discovery.get_active_peers().items():
                print(f"{username} ({status}) - {ip}")
        elif command == "chat":
            secure = input("Secure chat? (yes/no): ").strip().lower() == "yes"
            initiator.start_chat(secure)
        elif command == "history":
            initiator.view_chat_history()
