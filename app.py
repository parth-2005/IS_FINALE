# app.py
from messaging import MessagingService

def main():
    mode = input("Enter mode (server/client): ").lower()
    host = input("Enter host IP (default: 127.0.0.1): ") or "127.0.0.1"
    port = int(input("Enter port (default: 5555): ") or 5555)

    service = MessagingService(host, port)
    service.start(mode)

if __name__ == "__main__":
    main()
