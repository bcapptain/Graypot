import paramiko
import json
import datetime
import os
import logging
import socket
import threading
import struct
import time
import zlib
from typing import Dict, Any, Optional
from paramiko.ssh_exception import SSHException
import urllib.request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define log directory and file path
LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "connection_attempts.json")

# Graylog GELF UDP settings
GRAYLOG_HOST = os.getenv('GRAYLOG_HOST', 'graylog')
GRAYLOG_PORT = int(os.getenv('GRAYLOG_PORT', '12201'))

# SSH port from environment variable
SSH_PORT = int(os.getenv('SSH_PORT', '22'))

def get_public_ip():
    """
    Get public IP by first checking environment variable, then trying online services.
    Returns the public IP or '0.0.0.0' if all methods fail.
    """
    # First check environment variable
    public_ip = os.getenv('PUBLIC_IP')
    if public_ip:
        logging.info("Using PUBLIC_IP from environment variable")
        return public_ip
        
    # Try ipinfo.io
    try:
        with urllib.request.urlopen('https://ipinfo.io/ip', timeout=3) as response:
            return response.read().decode('utf-8').strip()
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as e:
        logging.warning(f"Could not fetch public IP from ipinfo.io: {e}")
        
        # Try alternative service api.ipify.org
        try:
            with urllib.request.urlopen('https://api.ipify.org', timeout=3) as response:
                return response.read().decode('utf-8').strip()
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as e:
            logging.warning(f"Could not fetch public IP from ipify.org: {e}")
            
            # Last resort fallback
            logging.warning("Could not determine public IP, falling back to 0.0.0.0")
            return '0.0.0.0'

HOST_IP = get_public_ip()
logger.info(f"Host IP detected as: {HOST_IP}")

class GELFLogger:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.chunk_size = 8192

    def send(self, message: Dict[str, Any]) -> None:
        """Send a GELF message to Graylog."""
        try:
            # Add required GELF fields
            message['version'] = '1.1'
            message['timestamp'] = int(time.time())
            message['host'] = socket.gethostname()
            
            # Convert to JSON and compress
            json_message = json.dumps(message)
            compressed_message = zlib.compress(json_message.encode('utf-8'))
            
            # Send the message
            self.sock.sendto(compressed_message, (GRAYLOG_HOST, GRAYLOG_PORT))
        except Exception as e:
            logging.error(f"Failed to send GELF message: {str(e)}")
            logging.error(f"Message was: {message}")
            logging.error(f"Exception type: {type(e).__name__}")

    def _chunk_message(self, message: str) -> list:
        """Split large messages into chunks for UDP transmission."""
        chunks = []
        message_id = os.urandom(8)
        total_chunks = (len(message) + self.chunk_size - 1) // self.chunk_size
        
        for i in range(total_chunks):
            chunk_header = struct.pack('!ccQBB',
                b'\x1e', b'\x0f',  # GELF chunk magic numbers
                int.from_bytes(message_id, byteorder='big'),
                i, total_chunks)
            
            start = i * self.chunk_size
            end = min(start + self.chunk_size, len(message))
            chunk_data = message[start:end].encode('utf-8')
            
            chunks.append(chunk_header + chunk_data)
        
        return chunks

class SSH_Honeypot(paramiko.ServerInterface):
    def __init__(self):
        self.event = None
        self.log_file = LOG_FILE
        self.transport = None
        self.client_ip = None
        self.gelf_logger = GELFLogger()
        
        # Ensure log directory exists
        os.makedirs(LOG_DIR, exist_ok=True)

    def check_auth_password(self, username: str, password: str) -> int:
        """Log authentication attempts and always reject them."""
        try:
            if not self.client_ip:
                self.client_ip = self.transport.getpeername()[0]
            
            log_entry = {
                "version": "1.1",
                "host": "ssh-honeypot",
                "short_message": f"SSH login attempt from {self.client_ip}",
                "full_message": f"SSH login attempt from {self.client_ip} with username {username}",
                "timestamp": datetime.datetime.now().timestamp(),
                "level": 6,  # INFO level
                "_event_type": "auth_attempt",
                "_event_category": "authentication",
                "_event_outcome": "failure",
                "_source_ip": self.client_ip,
                "_source_port": self.transport.getpeername()[1],
                "_destination_ip": HOST_IP,
                "_destination_port": SSH_PORT,
                "_username": username,
                "_attempted_password": password,
                "_service": "ssh-honeypot"
            }
            
            self._log_attempt(log_entry)
            self.gelf_logger.send(log_entry)
            logger.info(f"Login attempt from {self.client_ip} - Username: {username}")
        except Exception as e:
            logger.error(f"Error in check_auth_password: {e}")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Accept all channel requests."""
        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username: str) -> str:
        """Allow password authentication."""
        return "password"

    def _log_attempt(self, log_entry: Dict[str, Any]) -> None:
        """Log attempts to JSON file."""
        try:
            # Read existing logs
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []

            # Append new log entry
            logs.append(log_entry)

            # Write back to file
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
            logger.info(f"Logged attempt to {self.log_file}")
        except Exception as e:
            logger.error(f"Error logging attempt: {e}")

def handle_client(client, addr, host_key):
    """Handle individual client connections."""
    client_ip = addr[0]
    gelf_logger = GELFLogger()
    
    # Log connection attempt
    connection_entry = {
        "version": "1.1",
        "host": "ssh-honeypot",
        "short_message": f"SSH connection from {client_ip}",
        "full_message": f"SSH connection attempt from {client_ip}:{addr[1]}",
        "timestamp": datetime.datetime.now().timestamp(),
        "level": 6,  # INFO level
        "_event_type": "connection",
        "_event_category": "network",
        "_event_outcome": "unknown",
        "_source_ip": client_ip,
        "_source_port": addr[1],
        "_destination_ip": HOST_IP,
        "_destination_port": SSH_PORT,
        "_network_protocol": "ssh",
        "_network_transport": "tcp",
        "_service": "ssh-honeypot"
    }
    
    try:
        t = paramiko.Transport(client)
        t.set_log_channel('paramiko')
        t.local_version = "SSH-2.0-OpenSSH_8.2p1"
        t.remote_version = "SSH-2.0-OpenSSH_8.2p1"
        t.add_server_key(host_key)
        
        server = SSH_Honeypot()
        server.transport = t
        server.client_ip = client_ip
        
        t.start_server(server=server)
        connection_entry["_event_outcome"] = "success"
        
        channel = t.accept(20)
        if channel is not None:
            channel.send("Access denied.\n")
            channel.close()
        
        t.close()
    except SSHException as e:
        connection_entry["_event_outcome"] = "failure"
        connection_entry["_error_message"] = str(e)
        connection_entry["_error_type"] = "SSHException"
        logger.warning(f"SSH protocol error from {client_ip}: {e}")
    except Exception as e:
        connection_entry["_event_outcome"] = "failure"
        connection_entry["_error_message"] = str(e)
        connection_entry["_error_type"] = e.__class__.__name__
        logger.error(f"Error handling client {client_ip}: {e}")
    finally:
        server = SSH_Honeypot()
        server._log_attempt(connection_entry)
        gelf_logger.send(connection_entry)
        client.close()

def main():
    sock = None
    try:
        # Ensure log directory exists
        os.makedirs(LOG_DIR, exist_ok=True)
        
        # Generate host key
        host_key = paramiko.RSAKey.generate(2048)
        
        # Create socket and bind to port SSH_PORT
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', SSH_PORT))
        sock.listen(5)
        
        logger.info(f"SSH Honeypot started on port {SSH_PORT}")
        logger.info(f"Using host IP: {HOST_IP}")
        logger.info(f"Log file location: {LOG_FILE}")
        logger.info(f"Graylog forwarding enabled - Host: {GRAYLOG_HOST}, Port: {GRAYLOG_PORT}")
        
        while True:
            client, addr = sock.accept()
            logger.info(f"Connection from {addr[0]}:{addr[1]}")
            
            # Handle each client in a separate thread
            client_handler = threading.Thread(
                target=handle_client,
                args=(client, addr, host_key)
            )
            client_handler.daemon = True
            client_handler.start()
            
    except Exception as e:
        logger.error(f"Error in main loop: {e}")
    finally:
        if sock:
            sock.close()

if __name__ == "__main__":
    main()
