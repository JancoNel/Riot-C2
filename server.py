import socket
import threading
import os
import shutil
import secrets
import string

clients = {}
client_id_counter = 1
message_directory = 'client_messages'
archived_directory = 'archived_messages'

if not os.path.exists(message_directory):
    os.makedirs(message_directory)

if not os.path.exists(archived_directory):
    os.makedirs(archived_directory)

def has_less_than(var, num_chars):
    """Check if the variable has fewer than num_chars characters."""
    if isinstance(var, str):
        return len(var) < num_chars
    else:
        return False  # Handle cases where var is not a string

class ClientHandler(threading.Thread):
    def __init__(self, client_socket, client_id, addr):
        super().__init__()
        self.client_socket = client_socket
        self.client_id = client_id
        self.addr = addr
        self.running = True
        self.message_file = os.path.join(message_directory, f'client_{client_id}.txt')
    
    def run(self):
        print(f"Client {self.client_id} connected from {self.addr}")
        self.client_socket.send(f"Your client ID is {self.client_id}".encode('ascii'))
        with open(self.message_file, 'a') as file:
            file.write(f"Client {self.client_id} connected from {self.addr}\n")
        while self.running:
            try:
                message = self.client_socket.recv(1024).decode('ascii')
                if not message:
                    break
                if has_less_than(message, 100):
                    print(f"Client {self.client_id}: {message}")
                else:
                    print(f"Massive data recieved from {self.client_id} check history for details")
                with open(self.message_file, 'a') as file:
                    file.write(f"Client {self.client_id}: {message}\n")
                #response = f"Client {self.client_id}: {message}"
                #self.client_socket.send(response.encode('ascii'))
            except ConnectionResetError:
                break
        
        print(f"Client {self.client_id} disconnected")
        self.archive_message_file()
        self.client_socket.close()
        del clients[self.client_id]
    
    def stop(self):
        self.running = False

    def archive_message_file(self):
        random_name = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        new_path = os.path.join(archived_directory, f'client_{self.client_id}_{random_name}.txt')
        shutil.move(self.message_file, new_path)
        print(f"Archived message file for Client {self.client_id} to {new_path}")

class Server:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.client_id_counter = 1
        self.selected_client_id = None  # Track selected client

    def start(self):
        print(f"Server started at {self.host} on port {self.port}")
        threading.Thread(target=self.accept_clients).start()
        self.command_interface()

    def accept_clients(self):
        global clients
        while True:
            client_socket, addr = self.server_socket.accept()
            client_id = self.client_id_counter
            clients[client_id] = client_socket
            client_handler = ClientHandler(client_socket, client_id, addr)
            client_handler.start()
            self.client_id_counter += 1

    def command_interface(self):
        while True:
            if self.selected_client_id is not None:
                prompt = f"Client {self.selected_client_id}> "
            else:
                prompt = "> "
            command = input(prompt)
            if command == "list":
                self.list_clients()
            elif command == "select":
                self.select_client()
            elif command == "send":
                self.send_message()
            elif command == "stop":
                self.stop_client()
            elif command == "deselect":
                self.deselect_client()
            elif command == "show":
                self.show_message_history()
            elif command == "help":
                self.show_help()
            elif command == "exit":
                break
            elif command == "cls" or command == "clear":
                os.system('cls')
            elif command == "debug":
                kennedy = 0
                while kennedy == 0:
                    prompt = input("Code: ")
                    if prompt == 'exit':
                        kennedy = 1
                    else:
                        exec(prompt)
            elif command == "" or command == " ":
                continue
            else:
                if self.selected_client_id is not None:
                    message = command
                    self.send_message_to_client(self.selected_client_id, message)
                if self.selected_client_id is None:
                    message = command
                    for client_id, client_socket in clients.items():
                        anderson = client_socket.getpeername()
                        self.send_message_to_client(client_id, message)
                else:
                    print("No client selected")

    def select_client(self):
        client_id = int(input("Enter client ID: "))
        if client_id in clients:
            self.selected_client_id = client_id
            print(f"Selected Client {client_id}")
        else:
            print(f"No client with ID {client_id}")

    def send_message(self):
        if self.selected_client_id is not None:
            message = input("Enter message: ")
            self.send_message_to_client(self.selected_client_id, message)
        else:
            print("No client selected")

    def stop_client(self):
        if self.selected_client_id is not None:
            self.stop_client(self.selected_client_id)
            self.selected_client_id = None
        else:
            print("No client selected")

    def deselect_client(self):
        self.selected_client_id = None
        print("Deselected client")

    def send_message_to_client(self, client_id, message):
        if client_id in clients:
            client_socket = clients[client_id]
            client_socket.send(message.encode('ascii'))
            with open(os.path.join(message_directory, f'client_{client_id}.txt'), 'a') as file:
                file.write(f"Server to Client {client_id}: {message}\n")
            print(f"Payload sent to Client {client_id}: {message}")
        else:
            print(f"No client with ID {client_id}")

    def stop_client(self, client_id):
        if client_id in clients:
            client_socket = clients[client_id]
            client_handler = [t for t in threading.enumerate() if t.name == f"Thread-{client_id}"][0]
            client_handler.stop()
            client_socket.close()
            del clients[client_id]
            print(f"Stopped Client {client_id}")
        else:
            print(f"No client with ID {client_id}")

    def list_clients(self):
        print("Connected clients:")
        for client_id, client_socket in clients.items():
            addr = client_socket.getpeername()
            print(f"Client {client_id}: {addr}")

    def show_message_history(self):
        for client_id in os.listdir(message_directory):
            with open(os.path.join(message_directory, client_id), 'r') as file:
                if self.selected_client_id == None or self.selected_client_id == 'None':
                    print(f"Message history for {client_id}:")
                    print(file.read())
                    print("")
                elif int(self.selected_client_id) == int(client_id):
                    print(file.read())
                    print("")
                else:
                    print(f"Error , {client_id}")

    def show_help(self):
        help_text = """
Available commands:
  list          - List all connected clients
  select        - Select a client by ID
  stop          - Stop the selected client
  deselect      - Deselect the current client
  show          - Show message history of all clients
  help          - Show this help message
  exit          - Exit the server
"""
        print(help_text)

if __name__ == "__main__":
    server = Server()
    server.start()
