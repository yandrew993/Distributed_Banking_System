import socket  # Library for low-level networking
import threading  # Enables multi-threading for handling multiple clients
import ssl  # Provides support for SSL/TLS connections
import signal  # Used to handle system signals for graceful shutdown
import sys  # Provides system-specific parameters and functions
import os  # Used for interacting with the operating system
from flask import Flask, jsonify  # Flask is a micro web framework, jsonify helps return JSON responses
from multiprocessing import Process  # Allows running Flask in a separate process
from Crypto.Cipher import AES  # Implements AES encryption/decryption
from Crypto.Util.Padding import pad, unpad  # Used to pad and unpad data for AES
import base64  # Encodes and decodes data in Base64 format

# Initialize Flask application for server monitoring
app = Flask(__name__)

# Global variable to store server status for monitoring
server_status = {"connections": 0, "tasks_processed": 0}

# Flask route for server status monitoring
@app.route('/status', methods=['GET'])
def status():
    """Return server status as a JSON response."""
    return jsonify(server_status)

def run_flask():
    """Run the Flask app on port 5000."""
    app.run(port=5000, debug=False, use_reloader=False)

# AES encryption setup
SECRET_KEY = b'sixteen byte key'  # 16-byte secret key for AES encryption

def decrypt_data(encrypted_data):
    """Decrypt AES-encrypted data.
    Args:
        encrypted_data (str): Base64 encoded AES encrypted string.
    Returns:
        str: Decrypted plaintext.
    """
    encrypted_bytes = base64.b64decode(encrypted_data)  # Decode Base64 string
    iv = encrypted_bytes[:16]  # Extract the initialization vector (IV)
    ct = encrypted_bytes[16:]  # Extract the ciphertext
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)  # Create AES cipher with IV
    decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')  # Decrypt and remove padding
    return decrypted

def handle_task(client_socket, client_address):
    """Handle a single client's tasks in a thread.
    
    Args:
        client_socket (ssl.SSLSocket): The client's SSL-wrapped socket.
        client_address (tuple): The client's (IP, port) address.
    """
    global server_status  # Access global server status
    try:
        print(f"Connection from {client_address} has been established.")
        server_status["connections"] += 1  # Increment connection count

        while True:
            # Receive encrypted data from the client
            encrypted_data = client_socket.recv(1024).decode('utf-8')
            if not encrypted_data:
                print(f"Client {client_address} disconnected.")
                break

            try:
                # Decrypt the received data
                task_data = decrypt_data(encrypted_data)
                print(f"Decrypted task from {client_address}: {task_data}")
            except Exception as e:
                print(f"Decryption error from {client_address}: {e}")
                break

            # Simulate task processing based on the task received
            if task_data.lower() == "check balance":
                result = "Balance: $500"  # Respond with balance
            elif task_data.lower().startswith("transfer"):
                result = "Transaction Successful"  # Respond with success message
            elif task_data.lower().startswith("update contact"):
                result = "Contact Information Updated"  # Confirm contact update
            else:
                result = "Invalid Request"  # Handle invalid tasks

            # Increment tasks processed counter
            server_status["tasks_processed"] += 1

            # Send the result back to the client
            client_socket.send(result.encode('utf-8'))
    except (ConnectionResetError, BrokenPipeError):
        print(f"Client {client_address} unexpectedly disconnected.")
    except Exception as e:
        print(f"Error handling task from {client_address}: {e}")
    finally:
        # Close the connection to the client
        client_socket.close()
        print(f"Connection from {client_address} closed.")

def signal_handler(sig, frame):
    """Handle shutdown signals (e.g., Ctrl+C)."""
    print("Server shutting down...")
    sys.exit(0)

def start_server():
    """Start the multi-threaded SSL server."""
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Bind to all available interfaces on port 12345
    server_socket.listen(5)  # Allow up to 5 queued connections
    print("Server is listening on port 12345...")

    # Paths to SSL certificate and private key
    certfile_path = os.path.join(os.getcwd(), "server.crt")
    keyfile_path = os.path.join(os.getcwd(), "server.key")

    try:
        # Configure SSL context for secure communication
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Create an SSL context
        context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)  # Load certificate and key
    except Exception as e:
        print(f"Failed to load certificate: {e}")
        sys.exit(1)

    while True:
        # Accept a client connection
        client_socket, client_address = server_socket.accept()

        # Wrap the client connection with SSL
        secure_socket = context.wrap_socket(client_socket, server_side=True)

        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_task, args=(secure_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    # Register signal handler for graceful shutdown on Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the Flask monitoring app in a separate process
    flask_process = Process(target=run_flask)
    flask_process.start()

    # Start the SSL server
    start_server()
