import socket
import threading
import http.server
import socketserver
from base64 import b64decode
import qrcode
import psutil
import datetime
import os
import sys

# User credentials
users = {"amir": "amir", "movie": "movie", "admin": "root", "guest": "guest"}
clients = []
http_clients = []  # Track HTTP clients
server = None
httpd = None
shared_directory = "."

# ------------------- SOCKET SERVER FUNCTIONS -------------------

def handle_client(client_socket, client_address):
    authenticated = False
    while not authenticated:
        credentials = client_socket.recv(1024).decode('utf-8').split(":")
        if len(credentials) < 2:
            client_socket.send("AUTH_FAIL".encode('utf-8'))
            remove(client_socket)
            break
        username, password = credentials[0], credentials[1]
        if users.get(username) == password:
            client_socket.send("AUTH_SUCCESS".encode('utf-8'))
            authenticated = True
        else:
            client_socket.send("AUTH_FAIL".encode('utf-8'))
            remove(client_socket)
            break

    if authenticated:
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    print(f"{client_address[0]}: {message}")
                    broadcast(f"{username}: {message}", client_socket)
                else:
                    remove(client_socket)
                    break
            except:
                continue

def broadcast(message, connection):
    for client in clients:
        if client != connection:
            try:
                client.send(message.encode('utf-8'))
            except:
                remove(client)

def remove(connection):
    if connection in clients:
        clients.remove(connection)

def start_server(port):
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(100)
    server_ip = socket.gethostbyname(socket.gethostname())
    print(f"\nSocket started at {server_ip}:{port}")
    print("Feel Free to work while SOCKET server runs in background...")

    while True:
        client_socket, client_address = server.accept()
        clients.append((client_socket, client_address))  # Track both the socket and address
        print(f"{client_address[0]} connected")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()
def stop_server():
    global server
    if server:
        server.close()  # Close the socket server
        print("Socket server stopped.")

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

# ------------------- QR CODE GENERATION -------------------

def generate_qr_code(port):
    http_server_ip = socket.gethostbyname(socket.gethostname())
    url = f"http://{http_server_ip}:{port}"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_path = "server_qr.png"
    img.save(img_path)
    print(f"QR code saved as {img_path}")

# ------------------- SYSTEM INFO -------------------

def get_system_info():
    print("\n--- System Information ---")
    print(f"⦿ CPU Usage: {psutil.cpu_percent(interval=1)}%")
    print(f"⦿ Memory Usage: {psutil.virtual_memory().percent}%")
    print(f"⦿ Disk Usage: {psutil.disk_usage('/').percent}%")
    net_io = psutil.net_io_counters()
    print(f"⦿ Network Usage: 🠑 Sent: {net_io.bytes_sent / (1024 * 1024):.2f} MB, 🠗 Received: {net_io.bytes_recv / (1024 * 1024):.2f} MB")
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
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            username = input("Enter new username: ")
            password = input("Enter new password: ")
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
            print("Invalid choice, please try again.")

# ------------------- CONNECTED DEVICES -------------------

def view_connected_devices():
    print("\n--- Connected Devices ---")
    
    # For socket clients
    if clients:
        print("Socket clients connected:")
        for client_socket, client_address in clients:
            print(f" - {client_address[0]}:{client_address[1]}")
    else:
        print("No socket clients connected.")

    # For HTTP clients
    if http_clients:
        print("\nHTTP clients connected:")
        for client_ip in http_clients:
            print(f" - {client_ip}")
    else:
        print("No HTTP clients connected.")

#--------------------------------------------------
# Function to ask the user if they want to return to the main menu or exit
def prompt_return_to_main():
    user_input = input("\nDo you want to return to the main menu? (y/n):\n ").strip().lower()
    if user_input != 'y':
        print("Exiting...")
        stop_server()
        stop_http_server()
        sys.exit(0)
# ------------------- MAIN MENU -------------------

if __name__ == "__main__":
    while True:
        print("\nConnectPlus-CLI")
        print("1. Start Socket Server")
        print("2. Stop Socket Server")
        print("3. Start HTTP Server")
        print("4. Stop HTTP Server")
        print("5. Generate QR Code")
        print("6. Show System Info")
        print("7. Manage Users")
        print("8. View Connected Devices")
        print("99. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            port = int(input("Enter socket server port: "))
            threading.Thread(target=start_server, args=(port,), daemon=True).start()
            prompt_return_to_main()

        elif choice == "2":
            stop_server()
            prompt_return_to_main()

        elif choice == "3":
            port = int(input("Enter HTTP server port: "))
            threading.Thread(target=start_http_server, args=(port,), daemon=True).start()
            prompt_return_to_main()

        elif choice == "4":
            stop_http_server()
            prompt_return_to_main()

        elif choice == "5":
            port = int(input("Enter HTTP port for QR code: "))
            generate_qr_code(port)
            prompt_return_to_main()

        elif choice == "6":
            get_system_info()
            prompt_return_to_main()

        elif choice == "7":
            manage_users()
        elif choice == "8":
            view_connected_devices()
            prompt_return_to_main()

        elif choice == "99":
            print("Exiting...")
            stop_server()
            stop_http_server()
            sys.exit(0)
        else:
            print("Invalid choice, please try again.")
