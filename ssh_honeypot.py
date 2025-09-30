# ssh_honeypot.py
# ----------------
# Lightweight SSH honeypot module.
# This file defines:
# - file/paths and logging setup,
# - a Server class that implements Paramiko's ServerInterface callbacks,
# - an emulated shell that interacts with connecting clients,
# - a per-client handler that performs the SSH handshake and dispatches the shell,
# - a honeypot(...) function that opens a listening socket and accepts clients.
#
# Important: keep this project inside an isolated VM/container when exposing it to networks.

import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time
from pathlib import Path

# -----------------------------
# Configuration / constants
# -----------------------------

# The SSH protocol identification string (banner) we present to connecting clients.
# Real SSH servers usually send something like: "SSH-2.0-OpenSSH_8.9".
# We spoof our own value to appear like a plausible SSH server.
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# BASE DIRECTORY:
# Path(__file__) is the path to this file (ssh_honeypot.py).
# .parent gives the folder that contains this file (the 'honeypot' folder).
# Using the script folder ensures file lookups are relative to the project location,
# which makes the project portable (you can move the folder and the paths still work).
base_dir = Path(__file__).parent

# Paths to static files and logs (constructed relative to base_dir).
# - server.key: the SSH host private key (must exist).
# - creds_audits.log: stores attempted usernames/passwords.
# - cmd_audits.log: stores commands captured from the emulated shell.
server_key = base_dir / 'static' / 'server.key'
creds_audits_log_local_file_path = base_dir / 'log_files' / 'creds_audits.log'
cmd_audits_log_local_file_path = base_dir / 'log_files' / 'cmd_audits.log'

# Load the SSH server host key from disk.
# This key is presented to clients during the SSH handshake so clients can
# identify the server. We use Paramiko's helper to load the private key file.
# If the file is missing or invalid, this line will raise an exception.
host_key = paramiko.RSAKey.from_private_key_file(str(server_key))

# -----------------------------
# Logging setup
# -----------------------------
# We create two separate named loggers:
# 1) funnel_logger (for commands observed in the emulated shell)
# 2) creds_logger (for username/password attempts)
#
# Each logger writes to a rotating file so logs do not grow without bound:
# - maxBytes: rotate after this many bytes (small value used here for demo)
# - backupCount: how many rotated files to keep

# Simple formatter: we only write the message itself (no extra timestamp/level).
logging_format = logging.Formatter('%(message)s')

# logger for commands (shell activity)
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(str(cmd_audits_log_local_file_path), maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# logger for credentials (auth attempts)
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(str(creds_audits_log_local_file_path), maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# -----------------------------
# ServerInterface subclass
# -----------------------------
# Paramiko calls methods on this class during the SSH handshake and channel requests.
# By overriding these methods we control authentication, channel approval, and PTY/shell handling.

class Server(paramiko.ServerInterface):
    """
    Server implements callbacks that Paramiko uses during an SSH connection.
    - client_ip: IP address of the remote client (used for logging).
    - input_username / input_password: optional credentials; if provided,
      only the exact username/password pair will be accepted (useful for tests).
      If they are left as None, the server accepts any password (typical for honeypots).
    """

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()   # event used to signal when a shell was requested
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        """
        Called when the client requests a new channel.
        'kind' is a string like 'session' (interactive shell), 'direct-tcpip', etc.
        We only accept 'session' channels so the client can request a shell/exec.
        """
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        # Implicitly returns None (deny) for other channel kinds.

    def get_allowed_auths(self, username):
        """
        Called to tell the client which authentication methods are allowed.
        We return 'password' so the client will try password authentication.
        """
        return "password"

    def check_auth_password(self, username, password):
        """
        Called when the client attempts password authentication.
        We log every attempt (IP, username, password) and then accept or reject
        depending on whether input_username/input_password were supplied at startup.
        """
        # Log to both loggers: a human-readable funnel log and a CSV-like creds log.
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')

        # If specific credentials were provided when starting the honeypot,
        # accept only that pair. Otherwise accept everything (honeypot behavior).
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            # Accept all credentials (capture them in logs above).
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        """
        Called when the client requests an interactive shell on a session channel.
        We set an event so the handler knows a shell was requested and return True to accept.
        """
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """
        Called when the client requests a PTY (pseudo-terminal).
        Returning True allows programs on the client to behave like a normal terminal.
        """
        return True

    def check_channel_exec_request(self, channel, command):
        """
        Called when the client requests to execute a single command (ssh user@host command).
        We accept it. To capture such commands you could log `command` here.
        """
        # command is bytes; converting or logging could be added here.
        return True

# -----------------------------
# Helper: readable conversion
# -----------------------------
def bytes_to_readable(b: bytes) -> str:
    r"""
    Convert raw bytes to a human-friendly representation:
    - printable ASCII characters (32..126) are shown as-is
    - CR (13) shown as <CR>, LF (10) shown as <LF>, TAB (9) as <TAB>
    - control chars 1..26 shown as ^A .. ^Z (so 3 -> ^C)
    - NUL (0) as <NUL>
    - other non-printable bytes as \xNN
    This keeps log output readable while preserving non-printable information.
    """
    parts = []
    for byte in b:
        if 32 <= byte <= 126:
            parts.append(chr(byte))
        elif byte == 13:
            parts.append('<CR>')
        elif byte == 10:
            parts.append('<LF>')
        elif byte == 9:
            parts.append('<TAB>')
        elif byte == 0:
            parts.append('<NUL>')
        elif 1 <= byte <= 26:
            parts.append('^' + chr(byte + 64))
        else:
            parts.append(f'\\x{byte:02x}')
    return ''.join(parts)

# -----------------------------
# Emulated shell
# -----------------------------
def emulated_shell(channel, client_ip):
    """
    A simple interactive shell emulator. It:
    - sends a prompt,
    - reads input one byte at a time,
    - echoes typed characters back to the client (so typing looks real),
    - collects bytes until Enter (CR) is pressed, then handles the command,
    - logs commands in a readable form,
    - closes the session if the client sends Ctrl-C (ETX, 0x03) or disconnects.

    Parameters:
    - channel: Paramiko Channel object (represents the session's I/O).
    - client_ip: string with client's IP (used in logs).
    """
    # initial prompt (bytes)
    try:
        channel.send(b"caplok123@abdelhak$ ")
    except Exception:
        return  # channel is already closed

    command = b""
    while True:
        try:
            char = channel.recv(1)  # read one byte
        except Exception:
            break  # socket error or channel closed

        if not char:
            # remote closed connection
            break

        # echo the character back so the remote terminal shows what was typed
        try:
            channel.send(char)
        except Exception:
            break

        # handle Ctrl-C (ASCII 3) by closing the session
        if char == b'\x03':
            # log readable ^C and close channel
            funnel_logger.info(f'Command : ##^C## executed by {client_ip}')
            try:
                channel.send(b"^C\r\n")
            except Exception:
                pass
            try:
                channel.close()
            except Exception:
                pass
            return
        if char == b'\x7f':  # backspace
            if len(command) > 0:
                command = command[:-1]            # remove last character from buffer
                channel.send(b'\b \b')           # erase character visually on client



        # accumulate into command buffer
        command += char

        # when Enter (CR) is received, process the command
        if char == b"\r":
            cmd_stripped = command.strip()  # bytes without leading/trailing whitespace/newlines
            # prepare a readable string for logging (decode safely and mark non-printables)
            readable_cmd = bytes_to_readable(cmd_stripped)

            # emulate a few simple shell commands
            if cmd_stripped == b'exit':
                # close without further output
                funnel_logger.info(f'Command : ##{readable_cmd}## executed by {client_ip}')
                try:
                    channel.close()
                except Exception:
                    pass
                return

            elif cmd_stripped == b'pwd':
                response = b"\n" + b"\\usr\\local" + b"\r\n"
                funnel_logger.info(f'Command : ##{readable_cmd}## executed by {client_ip}')

            elif cmd_stripped == b'whoami':
                response = b"\n" + b"caplok123" + b"\r\n"
                funnel_logger.info(f'Command : ##{readable_cmd}## executed by {client_ip}')

            elif cmd_stripped == b'ls':
                response = b"\n" + b"jumpbox1.conf" + b"\r\n"
                funnel_logger.info(f'Command : ##{readable_cmd}## executed by {client_ip}')

            elif cmd_stripped == b'cat jumpbox1.conf':
                response = b"\n" + b"Go to deeboodah.com" + b"\r\n"
                funnel_logger.info(f'Command : ##{readable_cmd}## executed by {client_ip}')

            else:
                # default behavior: echo the command back in the shell
                # log readable form
                response = b"\n" + cmd_stripped + b"\r\n"
                funnel_logger.info(f'Command : ##{readable_cmd}## executed by {client_ip}')

            # send response and show new prompt (if channel still open)
            try:
                channel.send(response)
                channel.send(b"caplok123@abdelhak$ ")
            except Exception:
                # if we fail to send, end the session loop
                break

            command = b""  # reset for next command

    # cleanup: try to close channel, ignore errors
    try:
        channel.close()
    except Exception:
        pass

# -----------------------------
# Per-client handler
# -----------------------------
def client_handle(client, addr, username, password, tarpit=False):
    """
    Handle a single client connection.
    - client: the raw TCP socket returned by socket.accept()
    - addr: (ip, port) tuple for the remote endpoint
    - username/password: optional credentials to require for successful auth
    - tarpit: if True, send a slowed banner to tie up the client's session for a while

    This function:
    1) wraps the socket with Paramiko.Transport (SSH layer),
    2) adds the server host key and starts the SSH server handshake using Server(),
    3) waits for a session channel,
    4) optionally sends a banner slowly (tarpit) or normally,
    5) runs emulated_shell(channel, client_ip) to interact with the client,
    6) closes transport and socket at the end.
    """
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")  # simple console feedback for dev

    transport = None
    try:
        # Wrap the accepted socket with Paramiko's Transport (which implements SSH protocol)
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER  # set custom identification banner

        # Create our Server handler (will be called during handshake)
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)  # present our host key to the client
        transport.start_server(server=server)  # begin SSH server handshake & auth

        # Wait for the client to open a channel (e.g., a session for shell)
        channel = transport.accept(100)  # wait up to 100 seconds
        if channel is None:
            print("No channel was opened.")
            return

        # A typical login banner text shown by many Unix systems after auth.
        standard_banner = b"Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"

        try:
            if tarpit:
                # In tarpit mode we send the banner slowly (byte-by-byte) to slow attackers.
                # NOTE: keep the delay modest so this thread doesn't block forever.
                endless_banner = standard_banner * 10  # repeat banner 10 times (adjust as you like)
                for b in endless_banner:
                    # 'b' here is an int (0..255) because endless_banner is bytes; wrap to bytes object
                    channel.send(bytes([b]))
                    time.sleep(0.08)  # small delay between bytes
            else:
                # send the whole banner at once
                channel.send(standard_banner)

            # hand control to the emulated interactive shell
            emulated_shell(channel, client_ip=client_ip)

        except Exception as error:
            # print to console; keep simple for this learning project
            print("Error while handling channel:", error)

    except Exception as error:
        print("Transport/server setup error:", error)
        print("!!! Exception !!!")

    finally:
        # Always try to close the transport and socket to free resources
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass

# -----------------------------
# Honeypot server main loop
# -----------------------------
def honeypot(address, port, username, password, tarpit=False):
    """
    Start the honeypot listener.
    - address: IP address to bind to (e.g., '0.0.0.0' to accept all interfaces)
    - port: TCP port to listen on (e.g., 2222)
    - username/password: optional credentials to enforce (None accepts any creds)
    - tarpit: if True, enable the slow-banner tarpit per-session

    This function blocks: it accepts connections and starts a new thread per client.
    """
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)  # queue up to 100 pending connections
    print(f"SSH server is listening on {address}:{port}.")

    while True:
        try:
            client, addr = socks.accept()  # blocking accept
            # Start a daemon thread to handle this client so main loop keeps accepting
            ssh_honeypot_thread = threading.Thread(
                target=client_handle,
                args=(client, addr, username, password, tarpit),
                daemon=True
            )
            ssh_honeypot_thread.start()

        except Exception as error:
            print("!!! Exception - Could not open new client connection !!!")
            print(error)

























