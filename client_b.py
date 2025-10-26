import socket
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 5000))
client.send(b"Bob")

bob_key = RSA.generate(2048)
bob_private_key = bob_key.export_key()
bob_public_key = bob_key.publickey().export_key().decode()

client.send(f"PUBKEY:{bob_public_key}".encode())

print("[Bob] Waiting for messages...")

session_key = None

while True:
    data = client.recv(8192)
    if not data:
        break

    msg = data.decode()
    if msg.startswith("MSG:"):
        sender, content = msg.split(":", 2)[1:]
        print(f"\n[Bob] Received from {sender}")

        try:
            if session_key is None:
                enc_key = base64.b64decode(content)
                cipher_rsa = PKCS1_OAEP.new(RSA.import_key(bob_private_key))
                session_key = cipher_rsa.decrypt(enc_key)
                print("[Bob] AES session key decrypted successfully.")
                continue

            payload = json.loads(content)
            nonce = base64.b64decode(payload['nonce'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            tag = base64.b64decode(payload['tag'])

            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

            print(f"[Bob] Encrypted: {payload['ciphertext']}")
            print(f"[Bob] Decrypted: {plaintext}")

            log = {'received': {'ciphertext': payload['ciphertext'], 'plaintext': plaintext}}
            with open('messages.json', 'a') as f:
                json.dump(log, f)
                f.write('\n')

        except Exception as e:
            print("[Bob] Error decrypting:", e)
