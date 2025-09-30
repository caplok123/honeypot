# SSH Honeypot

This is my first cybersecurity project: a simple SSH honeypot built in Python using **Paramiko**.  
It emulates a fake SSH server that accepts connections, logs credentials, and provides a small fake shell.  
(you'll find in this work a lot of comments in the code that will help you understand in each step what's happening.  
It helps me keep track and memorize the functionalities of certain parts of the code.  
I got the help of chatgpt with these comments :) )  

## Features  
- Logs username and password attempts  
- Fake shell with basic commands (`pwd`, `ls`, `whoami`, `cat`)  
- Detects exit or Ctrl+C to close the session  
- Tarpit mode: traps attackers with endless banners  

## Project Structure
honeypot/

├── honeypy.py # Entry point (main script with argparse)  
├── ssh_honeypot.py # Honeypot server implementation  
├── static/ # Contains server.key (not uploaded to GitHub)  
├── log_files/ # Stores logs (ignored in .gitignore)  


## Installation
1. Clone the repository :
```bash
git clone https://github.com/caplok123/honeypot.git
cd honeypot
```

2. Create a virtual environment :

```bash
python -m venv .venv

source .venv/bin/activate   # Linux / macOS
.venv\Scripts\activate      # Windows
```

3. Install dependencies : 

```bash
pip install -r requirements.txt
```

4. Generate a new server key(on your machine):

```bash
mkdir -p static
ssh-keygen -t rsa -b 2048 -f static/server.key
chmod 600 static/server.key
```

## Usage
To run the honeypot, provide the address and port:

```bash
python honeypy.py -a 192.168.1.2 -p 2222 -u testuser -w testpass
```

OPTIONS:
-a, --address: IP address to bind (e.g., 0.0.0.0)  
-p, --port: Port to listen on (e.g., 2222)  
-u, --username: Username for authentication  
-w, --password: Password for authentication  
-t, --tarpit: Enable tarpit mode (delays attackers with endless banner)  
you can provide both(username,password); if you provide none the honeypot accepts all creds (by design).  

Logs will be saved in cmd_audits.log.  
