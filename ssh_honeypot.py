##################################################################
# ssh_honeypot.py
# 
# Description: A honeypot that runs on localhost with a virtualized file system.
#              * Tested on Python 3.12
#              * Max authentication attempts set to 3, the default for OpenSSH.
##################################################################
# Instructions to run:
# - On server (directory with honeypot_alt.py) -
# 1. Install Paramiko:  pip install paramiko
# 2. Start honeypot:    python ssh_honeypot.py -p 2222
# - On client application -
# 3. SSH to honeypot:   ssh -p 2222 user@127.0.0.1
# 4. Start interacting with honeypot (ls, echo, cat, cp commands)
##################################################################
# --- Standard Python libraries ---
import os
import sys
import argparse
import socket
import re
# --- Non-standard Python libraries ---
import paramiko

current_directory = {"password.txt": "12345"} # A dictionary simulating the file system in the honeypot

# Server - A custom ServerInterface class that overrides Paramiko's default server settings
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.username = ""        # Stores client's username
        self.failed_attempts = 0  # Counter to track user's failed login attempts

    # check_auth_password() - "Checks" password of user before allowing into the server. The honeypot allows the user to login after exceeding 3 failed attempts
    def check_auth_password(self, username, password):
        self.failed_attempts += 1
        print(f"{username}: Login attempt {self.failed_attempts}")

        # Allow user to login if they exceed 3 failed attempts
        if self.failed_attempts > 2:
            print(f"{username}: Granting access after exceeding 3 failed attempts.")
            self.username = username
            self.failed_attempts = 0  # Reset counter
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    # check_channel_request() - Ensures only session channels are permitted (which is typical for interactive shells)
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    # check_channel_pty_request() - Allows clients access to a pseudo-terminal
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    # check_channel_shell_request() - Allow clients access to our custom shell
    def check_channel_shell_request(self, channel):
        return True

# get_host_key() - Gets host key within the server (generates one if it doesn't exist)
def get_host_key():
    if not os.path.exists("server_host_key"):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file("server_host_key")
    return paramiko.RSAKey(filename="server_host_key")

# ls_command() - Handles the ls command in honeypot; lists all files in the current directory 
def ls_command():
    # List files in the fake directory
    files = current_directory.keys()
    return " ".join(files)

# echo_command() - Handles the echo command in honeypot; either write content to file or echo content back to client
def echo_command(data):
    # Check if the data following this format: ''{content}'' > {file_name}
    echo_pattern = r"^''(.+?)''\s*>\s*(.+)$"
    match = re.match(echo_pattern, data)
    
    if match:
        # Extract the content and file name from the data
        content = match.group(1)
        file_name = match.group(2)
        current_directory[file_name] = content # Write content to a new file (or the existing file if it is there)
        return "" # Return an empty string, indicating the file has been written
    else:
        return data + "\r\n" # Echo the inputted text if the client doesn't follow the echo pattern to write a file

# cat_command() - Handles the cat command in honeypot; echoes the files content (if it exists)
def cat_command(data):
    file_names = data.split()   # Split data into separate file names based on whitespace
    data = ""                   # Store data to be sent to client

    # Perform cat command for each file mentioned in the command 
    for file in file_names:
        # 1. First check if file is a .txt file. If not return error for unknown file extension
        if ".txt" not in file:
            data = data + f"Unknown file extension\r\n"
        # 2. Check if file is in directory. If not, return "file not found" error
        else:
            if file in current_directory.keys():
                data = data + current_directory[file] + "\r\n"
            else:
                data = data + f"File {file} not found\r\n"
    
    return data # Return content from file(s)

# cp_command() - Handles the cp command in honeypot; copies content from source file to destination file
def cp_command(data):
    file_names = data.split()   # Split data into separate file names based on whitespace
    if(len(file_names) != 2):   # Return error if two file names are not passed
        return "Error: cp command should be called like this: \"cp source.txt destination.txt\"\r\n"
    
    source_name = file_names[0]
    destination_name = file_names[1]

    if(source_name not in current_directory.keys()): # Return error if source file does not exist
        return f"cp: cannot stat {source_name}: No such file or directory\r\n"
    
    # Create or overwrite destination file with source file's content
    current_directory[destination_name] = current_directory[source_name]
    return ""

# handle_command() - Parses command client entered and processes it. 
def handle_command(user_command:str):
    # Return early if the user entered nothing
    if(user_command.strip() == ""):
        return ""

    # Parse command
    params = user_command.split(maxsplit=1)
    system_command = params[0]
    data_to_send = ""

    # Perform the command (if there is one)
    if(system_command == "ls"):
        data_to_send = ls_command()
        if (data_to_send.strip() != ""):
            data_to_send = data_to_send + "\r\n"
    elif(system_command == "echo"):
        data = params[1]
        data_to_send = echo_command(data)
    elif(system_command == "cat"):
        data = params[1]
        if(data.strip() == ""):
            data_to_send = "Error: no file(s) passed to cat command\r\n"
        else:
            data_to_send = cat_command(data)
    elif(system_command == "cp"):
        data = params[1]
        data_to_send = cp_command(data)
    else:
        data_to_send = system_command + ": command not found\r\n"

    return data_to_send # Return data to be sent to the channel

# start_honeypot_server() - Starts up honeypot server and continuously handles clients
def start_honeypot_server(port:int):
    host_key = get_host_key() # Get host key for SSH

    # Setup socket to listen for connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))  # Listening on localhost (127.0.0.1) on specified port
    sock.listen(5)
    print(f"*** Honeypot server listening on localhost on port {port} ***")

    # Continuously process clients connecting to the honeypot
    while True:
        client, addr = sock.accept() # Accept client connection

        # Setup SSH connection
        transport = paramiko.Transport(client) # Create SSH session in paramiko.Transport()
        transport.add_server_key(host_key)     # Send key to client to verify server's identity
        server = Server()

        print(f"Got connection from {addr}")

        try:
            transport.start_server(server=server) # Negotiate new SSH session as the server

            # Wait for a session channel
            channel = transport.accept(10)
            if channel is None:
                print("No channel...")
                continue
            
            channel.settimeout(60) # Terminate connection when client is idle for 60 seconds
            
            # Continously process communication with client
            username = server.username
            shell_prompt = username + "@honeypot:/$ "
            input_buffer = "" # Buffer for accumulating client input
            channel.send(shell_prompt)
            while True:
                # Read data from the client
                recv_data = channel.recv(1024)
                # print("Recv data:", recv_data)
                data = recv_data.decode("utf-8")
                if not data:
                    break  # Exit if the client disconnects
                
                for char in data:
                    # * Backspace is pressed *
                    if char == '\x08' or char == '\b' or char == '\x7f':
                        # print("Entered backspace")
                        if input_buffer:  # Only backspace if there's something to delete
                            input_buffer = input_buffer[:-1]
                            channel.send('\x08 \x08')  # Send backspace, space, & backspace to erase the last character and move the cursor back
                    # * ENTER key is pressed *
                    elif char in ['\n', '\r']:  
                        channel.send("\r\n")  # Echo the newline

                        # Process entered input
                        print(f"{username}: Entered: {input_buffer}")
                        data_to_send = handle_command(input_buffer)
                        channel.send(data_to_send)
                        
                        # Create fresh shell prompt on client side
                        channel.send(shell_prompt)
                        input_buffer = ""  # Clear the buffer for the next input
                    # * Regular key is pressed by client *
                    else:
                        input_buffer += char  # Add character to the input buffer
                        channel.send(char)  # Echo character back to client
            channel.close() # Close channel
        except TimeoutError: # Print which user timed-out on server after being idle for 60 seconds
            print(f"{username}: Connection terminated - Timed out after 60 seconds")
        except Exception as e: # Print error on server if any other issues happen
            print(f"ERROR: {e}")
        finally:
            transport.close()

# main() - Where the main code is stored
def main():
    # Reading the commandline arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=int, required=True, help="Enter the port number where the ssh server will bind to.")
    args = parser.parse_args()

    # Start the honeypot
    try:
        start_honeypot_server(args.p)
    except KeyboardInterrupt:
        print("Ending honeypot...")
        sys.exit(-1)

if __name__ == "__main__":
    main()