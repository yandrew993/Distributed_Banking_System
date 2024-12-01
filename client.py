import asyncio
import ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Configure SSL context for secure communication with the server
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)  # Create an SSL context for authenticating the server
context.check_hostname = False  # Skip hostname verification (useful for testing environments)
context.verify_mode = ssl.CERT_REQUIRED  # Enforce server certificate verification
context.load_verify_locations("server.crt")  # Load the server's certificate for validation

# Encryption setup
SECRET_KEY = b'sixteen byte key'  # the encryption/decryption key.

def encrypt_data(data):
    """Encrypts data using AES encryption in CBC mode.

    Args:
        data (str): The plaintext string to encrypt.

    Returns:
        str: Base64-encoded string containing the IV and ciphertext.
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)  # Create an AES cipher object in CBC mode
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))  # Encrypt the padded plaintext
    iv = cipher.iv  # Initialization vector (IV) used for CBC mode
    encrypted = base64.b64encode(iv + ct_bytes).decode('utf-8')  # Combine IV and ciphertext, encode as Base64
    return encrypted

def decrypt_data(encrypted_data):
    """Decrypts AES-encrypted data.

    Args:
        encrypted_data (str): Base64-encoded string containing the IV and ciphertext.

    Returns:
        str: The decrypted plaintext string.
    """
    encrypted_bytes = base64.b64decode(encrypted_data)  # Decode the Base64-encoded string
    iv = encrypted_bytes[:16]  # Extract the IV (first 16 bytes)
    ct = encrypted_bytes[16:]  # Extract the ciphertext
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)  # Create an AES cipher with the IV
    decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')  # Decrypt and remove padding
    return decrypted

async def client_task(client_id, tasks):
    """Simulates a client that connects to the server, sends tasks, and receives responses.

    Args:
        client_id (int): Unique identifier for the client.
        tasks (list): List of tasks (strings) for the client to send to the server.
    """
    hostname = 'localhost'  # Server hostname
    port = 12345  # Server port
    try:
        # Establish a secure connection to the server
        reader, writer = await asyncio.open_connection(hostname, port, ssl=context)
        print(f"Client {client_id}: SSL connection established with the server.")

        for task in tasks:
            try:
                # Encrypt the task before sending
                encrypted_task = encrypt_data(task)
                writer.write(encrypted_task.encode())  # Send the encrypted task
                await writer.drain()  # Ensure the data is sent
                print(f"Client {client_id}: Sent task: {task}")

                # Wait for the server's encrypted response
                encrypted_response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                decrypted_response = encrypted_response.decode('utf-8')  # No need to decrypt plain responses
                print(f"Client {client_id}: Server response: {decrypted_response}")
            except Exception as e:
                print(f"Client {client_id}: Error during task processing: {e}")

        # Close the connection after all tasks are completed
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"Client {client_id}: Connection error: {e}")

async def main():
    """Simulates multiple clients sending tasks to the server."""
    # Prompt the user for the number of clients to simulate
    num_clients = int(input("Enter number of clients to simulate: "))

    # Each client is assigned a predefined set of tasks
    tasks_per_client = [
        [
            "Check Balance",  # Example task
            "Transfer $100 to Account XYZ",  # Example task
            "Update Contact Information"  # Example task
        ]
        for client_id in range(num_clients)
    ]

    # Create a list of asyncio tasks to simulate all clients concurrently
    tasks = []
    for client_id, client_tasks in enumerate(tasks_per_client, start=1):
        task = asyncio.create_task(client_task(client_id, client_tasks))  # Create a client task
        tasks.append(task)

    await asyncio.gather(*tasks)  # Run all client tasks concurrently

if __name__ == "__main__":
    asyncio.run(main())  # Run the asyncio event loop for the main function
