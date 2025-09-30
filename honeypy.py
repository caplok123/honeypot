# honeypy.py
# ----------------
# Simple command-line entrypoint for the SSH honeypot module.
# It accepts command-line options (address, port, optional credentials, tarpit flag)
# and then calls honeypot(...) to start the server.

import argparse
from ssh_honeypot import honeypot

if __name__ == "__main__":
    # Create a command-line argument parser.
    parser = argparse.ArgumentParser(description="Start the simple SSH honeypot.")
    # required network args
    parser.add_argument('-a', '--address', type=str, required=True, help="IP address to bind to (e.g. 0.0.0.0)")
    parser.add_argument('-p', '--port', type=int, required=True, help="TCP port to listen on (e.g. 2222)")
    # optional forced credentials (if provided, only these will succeed)
    parser.add_argument('-u', '--username', type=str, help="Optional username to accept (honeypot will accept only this if provided)")
    parser.add_argument('-w', '--password', type=str, help="Optional password to accept (honeypot will accept only this if provided)")
    # optional tarpit flag (slows client by sending a repeated banner slowly)
    parser.add_argument('-t', '--tarpit', action="store_true", help="Enable tarpit mode (slow banner sending)")

    args = parser.parse_args()

    # Normalize empty values to None so the honeypot knows "no specific creds provided"
    if not args.username:
        args.username = None
    if not args.password:
        args.password = None

    try:
        print("[-] Running SSH Honeypot...")
        # This call blocks: honeypot(...) listens forever until the process is interrupted.
        honeypot(args.address, args.port, args.username, args.password, args.tarpit)
    except KeyboardInterrupt:
        # clean keyboard exit (Ctrl-C) from the operator running the honeypot
        print("\nProgram exited.")
