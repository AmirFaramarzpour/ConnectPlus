import socket
import threading
import http.server
import socketserver
import customtkinter as ctk
from base64 import b64decode
import tkinter as tk
from tkinter import filedialog
from base64 import b64encode
import qrcode
from PIL import Image, ImageTk
import psutil
import datetime
import os 


users = {"amir": "amir", "movie": "movie", "admin":"root","guest":"guest"}  # Example user credentials
clients = []
server = None
httpd = None
shared_directory = "."

def handle_client(client_socket, client_address):
    authenticated = False
    while not authenticated:
        credentials = client_socket.recv(1024).decode('utf-8').split(":")
        username, password = credentials[0], credentials[1]
        if username in users and users[username] == password:
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
                    log_message(f"{client_address[0]}: {message}")
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

def start_server():
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', int(port_entry.get())))
    server.listen(100)
    server_ip = socket.gethostbyname(socket.gethostname())
    log_message(f"Socket server started at {server_ip}:{port_entry.get()}")
    log_message("Waiting for connections...")

    while True:
        client_socket, client_address = server.accept()
        clients.append(client_socket)
        log_message(f"{client_address[0]} connected")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

def stop_server():
    global server
    if server:
        for client in clients:
            client.close()
        server.close()
        log_message("Server stopped.")

def toggle_server():
    if server_switch.get():
        server_thread = threading.Thread(target=start_server)
        server_thread.start()
    else:
        stop_server()

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
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
                super().do_GET()
            else:
                self.do_AUTHHEAD()
                self.wfile.write(b'Not authenticated')


    def log_message(self, format, *args):
        log_http_message(f"GET request: {self.client_address[0]} - {format % args}")

def start_http_server():
    global httpd
    try:
        os.chdir(shared_directory)  # Change the working directory to the selected directory
        handler = AuthHandler
        httpd = socketserver.TCPServer(("0.0.0.0", int(http_port_entry.get())), handler)
        http_server_ip = socket.gethostbyname(socket.gethostname())
        log_http_message(f"HTTP server started at {http_server_ip}:{http_port_entry.get()}")
        httpd.serve_forever()
    except OSError as e:
        log_http_message(f"Error: {e}")
        stop_http_server()

def stop_http_server():
    global httpd
    if httpd:
        httpd.shutdown()
        log_http_message("HTTP server stopped.")

def toggle_http_server():
    if http_server_switch.get():
        http_server_thread = threading.Thread(target=start_http_server)
        http_server_thread.start()
    else:
        stop_http_server()

def select_directory():
    global shared_directory
    directory = filedialog.askdirectory()
    if directory:
        shared_directory = directory
        shared_directory_entry.delete(0, tk.END)
        shared_directory_entry.insert(0, shared_directory)
        log_message(f"Selected directory: {shared_directory}")

def add_user():
    username = new_user_entry.get()
    password = new_password_entry.get()
    if username and password:
        users[username] = password
        update_user_list()
        log_message(f"Added user: {username}")

def remove_user():
    username = new_user_entry.get()
    if username in users:
        del users[username]
        update_user_list()
        log_message(f"Removed user: {username}")
    else:
        log_message(f"User not found: {username}")

def update_user_list():
    user_textbox.configure(state=tk.NORMAL)
    user_textbox.delete(1.0, tk.END)
    for user in users:
        user_textbox.insert(tk.END, f"{user}\n")
    user_textbox.configure(state=tk.DISABLED)

def log_message(message):
    log_textbox.insert(ctk.END, f"{message}\n")
    log_textbox.see(ctk.END)

def log_http_message(message):
    http_log_textbox.insert(ctk.END, f"{message}\n")
    http_log_textbox.see(ctk.END)

#=============================================================================
def generate_qr_code():
    http_server_ip = socket.gethostbyname(socket.gethostname())
    url = f"http://{http_server_ip}:{http_port_entry.get()}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    img = img.resize((200, 200), Image.LANCZOS)  # Use Image.LANCZOS instead of Image.ANTIALIAS
    img = ImageTk.PhotoImage(img)

    qr_label.configure(image=img)
    qr_label.image = img

#=============================================================================

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_memory_usage():
    memory = psutil.virtual_memory()
    return memory.percent

def get_disk_usage():
    disk = psutil.disk_usage('/')
    return disk.percent

def get_network_usage():
    net_io = psutil.net_io_counters()
    return f"\n 🠑 Sent: {net_io.bytes_sent / (1024 * 1024):.2f} MB, \n 🠗 Received: {net_io.bytes_recv / (1024 * 1024):.2f} MB"

def get_battery_status():
    battery = psutil.sensors_battery()
    if battery:
        return f"🔋Battery: {battery.percent}%, Plugged in: {'Yes ☑' if battery.power_plugged else 'No ☒'}"
    else:
        return "Battery status not available"

def get_system_uptime():
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    return str(uptime).split('.')[0]  # Return uptime without microseconds

def update_monitor_textbox():
    cpu_usage = get_cpu_usage()
    memory_usage = get_memory_usage()
    disk_usage = get_disk_usage()
    network_usage = get_network_usage()
    battery_status = get_battery_status()
    system_uptime = get_system_uptime()

    monitor_textbox.configure(state=tk.NORMAL)
    monitor_textbox.delete(1.0, tk.END)
    monitor_textbox.insert(tk.END, f"CPU Usage: {cpu_usage}%\n")
    monitor_textbox.insert(tk.END, f"Memory Usage: {memory_usage}%\n")
    monitor_textbox.insert(tk.END, f"Disk Usage: {disk_usage}%\n")
    monitor_textbox.insert(tk.END, f"Network Usage: {network_usage}\n")
    monitor_textbox.insert(tk.END, f"{battery_status}\n")
    monitor_textbox.insert(tk.END, f"System Uptime: {system_uptime}\n")
    monitor_textbox.configure(state=tk.DISABLED)

    app.after(10000, update_monitor_textbox)  # Update every 10 second


#=============================================================================
# Apps and Layout settings:

app = ctk.CTk()
app.title("ConnectPlus [Server Side GUI]")
app.geometry("850x850")
app.resizable(True, True)

# Set the main window color using a custom frame
main_frame = ctk.CTkFrame(app, fg_color="#7C8363")
main_frame.pack(fill="both", expand=True, padx=20, pady=5)

# Server control section
server_control_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
server_control_frame.pack(pady=1, fill="x")

socket_label = ctk.CTkLabel(server_control_frame, text="🛜 HTTP|Socket server configuration", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10, anchor="w")
socket_label.grid(row=0, column=0, columnspan=3, padx=5, pady=5)
port_label = ctk.CTkLabel(server_control_frame, text="Port:", font=("Trebuchet MS", 12))
port_label.grid(row=1, column=1, padx=5, pady=5)
port_entry = ctk.CTkEntry(server_control_frame, corner_radius=10, placeholder_text="Enter port number")
port_entry.grid(row=1, column=2, padx=5, pady=5)

server_switch = ctk.CTkSwitch(server_control_frame, text="Start Socket Module (Messenger)", font=("Trebuchet MS", 12), command=toggle_server)
server_switch.grid(row=1, column=3, padx=5, pady=5)

#=============================================================================
# HTTP server control section
http_server_control_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
http_server_control_frame.pack(pady=1, fill="x")

# Create a parent frame to hold both sections side by side
qr_split_frame = ctk.CTkFrame(http_server_control_frame, fg_color="#31473A")
qr_split_frame.grid(row=0, column=0, columnspan=6, padx=10, pady=10, sticky="ew")

# Left section - HTTP server controls
http_server_controls = ctk.CTkFrame(qr_split_frame, fg_color="#31473A")
http_server_controls.grid(row=0, column=0, padx=5, pady=5, sticky="ns")

http_port_label = ctk.CTkLabel(http_server_controls, text="HTTP Port:", font=("Trebuchet MS", 12))
http_port_label.grid(row=0, column=0, padx=5, pady=5)
http_port_entry = ctk.CTkEntry(http_server_controls, corner_radius=10, placeholder_text="Enter port number")
http_port_entry.grid(row=0, column=1, padx=5, pady=5)

http_server_switch = ctk.CTkSwitch(http_server_controls, text="Start HTTP Server", font=("Trebuchet MS", 12), command=toggle_http_server)
http_server_switch.grid(row=0, column=3, padx=5, pady=5)

shared_directory_label = ctk.CTkLabel(http_server_controls, text="Shared Directory:", font=("Trebuchet MS", 12))
shared_directory_label.grid(row=1, column=0, padx=5, pady=5)
shared_directory_entry = ctk.CTkEntry(http_server_controls, corner_radius=10, placeholder_text="Select directory using browse button")
shared_directory_entry.grid(row=1, column=1, columnspan=4, padx=5, pady=5, sticky="ew")
browse_button = ctk.CTkButton(http_server_controls, text="Browse", font=("Trebuchet MS", 12), command=select_directory, corner_radius=10)
browse_button.grid(row=1, column=5, padx=5, pady=5)

# Right section - QR code
qr_code_frame = ctk.CTkFrame(qr_split_frame, fg_color="#31473A")
qr_code_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ns")

# QR Code button
qr_button = ctk.CTkButton(qr_code_frame, text="Generate QR Code", font=("Trebuchet MS", 12), command=generate_qr_code, corner_radius=10)
qr_button.grid(row=0, column=0, padx=5, pady=5)

# QR Code display label
qr_label = ctk.CTkLabel(qr_code_frame, text="QR Code will appear here", font=("Trebuchet MS", 8))
qr_label.grid(row=1, column=0, padx=10, pady=1)

# Create a parent frame to hold both sections side by side
split_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
split_frame.pack(pady=1, fill="both", expand=True)


#=============================================================================

# User management section
user_management_frame = ctk.CTkFrame(split_frame, fg_color="#31473A")
user_management_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ns")

user_management = ctk.CTkLabel(user_management_frame, text="🛗 User Management", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10)
user_management.grid(row=0, column=0, columnspan=1, padx=5, pady=1)

new_user_label = ctk.CTkLabel(user_management_frame, text="New User:", font=("Trebuchet MS", 12))
new_user_label.grid(row=1, column=0, padx=5, pady=1)
new_user_entry = ctk.CTkEntry(user_management_frame, corner_radius=10, placeholder_text="Enter username")
new_user_entry.grid(row=1, column=1, padx=5, pady=1)

new_password_label = ctk.CTkLabel(user_management_frame, text="New Password:", font=("Trebuchet MS", 12))
new_password_label.grid(row=2, column=0, padx=5, pady=1)
new_password_entry = ctk.CTkEntry(user_management_frame, corner_radius=10, show="*", placeholder_text="Enter password")
new_password_entry.grid(row=2, column=1, padx=5, pady=1)

add_user_button = ctk.CTkButton(user_management_frame, text="➕ Add User", command=add_user, corner_radius=10, font=("Trebuchet MS", 12))
add_user_button.grid(row=1, column=2, padx=5, pady=1)

remove_user_button = ctk.CTkButton(user_management_frame, text="➖ Remove User", command=remove_user, corner_radius=10, font=("Trebuchet MS", 12))
remove_user_button.grid(row=2, column=2, padx=5, pady=1)

user_list_label = ctk.CTkLabel(user_management_frame, text="Users:", font=("Trebuchet MS", 12))
user_list_label.grid(row=3, column=0, padx=5, pady=1)
user_textbox = ctk.CTkTextbox(user_management_frame, width=50, height=100, corner_radius=10, state=tk.DISABLED)
user_textbox.grid(row=4, column=0, columnspan=3, padx=5, pady=1, sticky="ew")
update_user_list()

#=============================================================================

# System resource monitoring section
monitor_frame = ctk.CTkFrame(split_frame, fg_color="#31473A")
monitor_frame.grid(row=0, column=1, padx=10, pady=10, sticky="ns")

monitor_label = ctk.CTkLabel(monitor_frame, text="⚙ Performance", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10, anchor="w")
monitor_label.pack(pady=(1, 0), padx=5, anchor="w")

monitor_textbox = ctk.CTkTextbox(monitor_frame, width=250, height=100, corner_radius=10)
monitor_textbox.pack(padx=5, pady=1, fill="both", expand=True)

# Call the function to start monitoring
update_monitor_textbox()

#=============================================================================

# Server log section
log_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
log_frame.pack(pady=1, fill="both", expand=True)

log_label = ctk.CTkLabel(log_frame, text="🖹 Socket Server Logs", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10, anchor="w")
log_label.pack(pady=(10, 0), padx=10, anchor="w")

log_textbox = ctk.CTkTextbox(log_frame, width=200, height=100, corner_radius=10)
log_textbox.pack(padx=10, pady=5, fill="both", expand=True)

# HTTP request log section
http_log_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
http_log_frame.pack(pady=1, fill="both", expand=True)

http_log_label = ctk.CTkLabel(http_log_frame, text="🖹 HTTP Get Requests", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10, anchor="w")
http_log_label.pack(pady=(10, 0), padx=10, anchor="w")

http_log_textbox = ctk.CTkTextbox(http_log_frame, width=200, height=100, corner_radius=10)
http_log_textbox.pack(padx=10, pady=5, fill="both", expand=True)

#=============================================================================

# Add copyright label with text wrapping
copyright_label = ctk.CTkLabel(
    main_frame, 
    text="© 2025 Amir Faramarzpour.\nGitHub.com/AmirFaramarzpour", 
    text_color="white", 
    font=("Trebuchet MS", 12, "bold"),
    corner_radius=4, 
    wraplength=380  # Set wrap length to fit within the right frame
)
copyright_label.pack(pady=(3, 3))

#=============================================================================
# Running the app
app.mainloop()
