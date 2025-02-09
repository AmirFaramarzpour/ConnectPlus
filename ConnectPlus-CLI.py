import socket
import threading
import http.server
import socketserver
from base64 import b64decode
import psutil
import datetime
import os
import sys

# User credentials
users = {"amir": "amir", "movie": "movie", "admin": "root", "guest": "guest"}
http_clients = []  # Track HTTP clients
httpd = None
shared_directory = "."

# ------------------- HTTP SERVER FUNCTIONS -------------------

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Secure Area\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if self.headers.get('Authorization') is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'No auth header received')
        else:
            auth_header = self.headers.get('Authorization')
            auth_decoded = b64decode(auth_header.split(' ')[1]).decode('utf-8')
            username, password = auth_decoded.split(':')

            if users.get(username) == password:
                # Track the HTTP client
                client_address = self.client_address[0]
                if client_address not in http_clients:
                    http_clients.append(client_address)
                super().do_GET()
            else:
                self.do_AUTHHEAD()
                self.wfile.write(b'Not authenticated')

    def log_message(self, format, *args):
        print(f"HTTP GET request: {self.client_address[0]} - {format % args}")

def start_http_server(port):
    global httpd
    try:
        os.chdir(shared_directory)
        handler = AuthHandler
        httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
        http_server_ip = socket.gethostbyname(socket.gethostname())
        print(f"\nHTTP server started at {http_server_ip}:{port}")
        print("Feel Free to work while HTTP server runs in background...")
        httpd.serve_forever()

    except OSError as e:
        print(f"Error: {e}")
        stop_http_server()

def stop_http_server():
    global httpd
    if httpd:
        httpd.shutdown()
        print("HTTP server stopped.")

# ------------------- SYSTEM INFO -------------------

def get_system_info():
    print("\n--- System Information ---")
    print(f"⦿ CPU Usage: {psutil.cpu_percent(interval=1)}%")
    print(f"⦿ Memory Usage: {psutil.virtual_memory().percent}%")
    print(f"⦿ Disk Usage: {psutil.disk_usage('/').percent}%")
    net_io = psutil.net_io_counters()
    print(f"⦿ Network Usage:  Sent: {net_io.bytes_sent / (1024 * 1024):.2f} MB,  Received: {net_io.bytes_recv / (1024 * 1024):.2f} MB")
    battery = psutil.sensors_battery()
    if battery:
        print(f"⦿ Battery: {battery.percent}%, Plugged in: {'Yes ⚡' if battery.power_plugged else 'No 🪫'}")
    print(f"⦿ System Uptime: {str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).split('.')[0]}")
    print("--------------------------")

# ------------------- USER MANAGEMENT -------------------

def manage_users():
    while True:
        print("\nUser Management")
        print("1. Add User")
        print("2. Remove User")
        print("3. List Users")
        print("4. Back to Main Menu")
        choice = input("Select option: ").strip()

        if choice == "1":
            username = input("New username: ")
            password = input("New password: ")
            users[username] = password
            print(f"User {username} added.")
        elif choice == "2":
            username = input("Enter username to remove: ")
            if username in users:
                del users[username]
                print(f"User {username} removed.")
            else:
                print("User not found.")
        elif choice == "3":
            print("Current users:")
            for user in users:
                print(f" - {user}")
        elif choice == "4":
            break
        else:
            print("Invalid, please try again.")

# ------------------- CONNECTED DEVICES -------------------

def view_connected_devices():
    print("\n--- Connected Devices ---")

    # For HTTP clients
    if http_clients:
        for client_ip in http_clients:
            print(f" - {client_ip}")
    else:
        print("No HTTP clients connected.")

# --------------------------------------------------
# Function to ask the user if they want to return to the main menu or exit
def prompt_return_to_main():
    user_input = input("\nReturn to the main menu? (Yes/No):\n ").strip().lower()
    if user_input != 'y':
        print("Shutdown ...")
        stop_http_server()
        sys.exit(0)

# ------------------- MAIN MENU -------------------

if __name__ == "__main__":
    print(r"""" 
  _________         .    .
(..       \_    ,  |\  /|
 \       O  \  /|  \ \/ /
  \______    \/ |   \  / 
     vvvv\    \ |   /  |
     \^^^^  ==   \_/   |
      `\_   ===    \.  |
      / /\_   \ /      |
      |/   \_  \|      /
             \________/

|.:: ConnectPlus™ ::.|
|-Basic command line-|
 """)
    while True:
        print("----------\nMain Menu\n----------\n")
        print("1. Start HTTP Server")
        print("2. Stop HTTP Server")
        print("3. System Resource Monitor")
        print("4. Users Authentication")
        print("5. Connected Devices")
        print("99. Exit")
        print("\nThis program is provided with ABSOLUTELY NO WARRANTY !")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            port = int(input("HTTP port (e.g. 8000): "))
            threading.Thread(target=start_http_server, args=(port,), daemon=True).start()
            prompt_return_to_main()

        elif choice == "2":
            stop_http_server()
            prompt_return_to_main()

        elif choice == "3":
            get_system_info()
            prompt_return_to_main()

        elif choice == "4":
            manage_users()

        elif choice == "5":
            view_connected_devices()
            prompt_return_to_main()

        elif choice == "99":
            print("Shutdown ...")
            stop_http_server()
            sys.exit(0)
        else:
            print("Invalid, please try again.")
