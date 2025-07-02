from fastapi import FastAPI, Request
from shared.crypto_utils import generate_key_pair, derive_shared_key, decrypt_message
from shared.identity_utils import generate_anonymous_id
from cryptography.hazmat.primitives import serialization
import base64

app = FastAPI()

anon_id = generate_anonymous_id()
private_key, public_key = generate_key_pair()
shared_key = None

@app.get("/")
def root():
    return {"peer2_id": anon_id}

@app.post("/exchange")
async def receive_key(request: Request):
    body = await request.json()
    peer_pub = serialization.load_pem_public_key(body["pub"].encode())

    global shared_key
    shared_key = derive_shared_key(private_key, peer_pub)

    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return {"pub": pem_pub}

@app.post("/receive")
async def receive_encrypted(request: Request):
    if not shared_key:
        return {"error": "Shared key not established yet."}

    body = await request.json()
    encrypted = base64.b64decode(body["data"])
    decrypted = decrypt_message(shared_key, encrypted)
    return {"decrypted_message": decrypted.decode()}
