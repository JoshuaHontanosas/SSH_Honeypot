# SSH_Honeypot
A honeypot that runs on localhost with a virtualized file system.

## How to run:
On server (directory with ssh_honeypot.py)
1. Install Paramiko:  pip install paramiko
2. Start honeypot:    python ssh_honeypot.py -p 2222

On client application:
1. SSH to honeypot:   ssh -p 2222 user@127.0.0.1
2. Start interacting with honeypot (ls, echo, cat, cp commands)
