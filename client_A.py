import socket
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 5000))
client.send(b"Alice")

alice_key = RSA.generate(2048)
alice_private_key = alice_key.export_key()
alice_public_key = alice_key.publickey().export_key().decode()

client.send(f"PUBKEY:{alice_public_key}".encode())

client.send("GETKEY:Bob".encode())
response = client.recv(8192).decode()

if response.startswith("PUBKEY"):
    bob_public_key = response.split(":", 2)[2]
else:
    print("[Alice] Bob not found on server yet. Start Bob first.")
    exit()

bob_pub = RSA.import_key(bob_public_key)

session_key = get_random_bytes(16)
cipher_rsa = PKCS1_OAEP.new(bob_pub)
enc_session_key = cipher_rsa.encrypt(session_key)

client.send(f"TO:Bob:{base64.b64encode(enc_session_key).decode()}".encode())
print("[Alice] Sent encrypted AES session key to Bob.")

while True:
    message = input("Enter message (or 'exit'): ")
    if message.lower() == "exit":
        break

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    payload = {
        'nonce': base64.b64encode(cipher_aes.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    }

    client.send(f"TO:Bob:{json.dumps(payload)}".encode())

    log = {'sent': {'plaintext': message, 'ciphertext': payload['ciphertext']}}
    with open('messages.json', 'a') as f:
        json.dump(log, f)
        f.write('\n')

    print("[Alice] Message sent.")
