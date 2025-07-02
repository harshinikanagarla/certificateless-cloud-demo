import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fastapi import FastAPI
from shared.crypto_utils import generate_key_pair, derive_shared_key, encrypt_message
from shared.identity_utils import generate_anonymous_id
from cryptography.hazmat.primitives import serialization
import base64
import requests
import os

app = FastAPI()

# Configurable URL (set this in Render or .env for local)
PEER2_URL =  "https://peer2-glitch-project.glitch.me/receive"

anon_id = generate_anonymous_id()
private_key, public_key = generate_key_pair()
shared_key = None

@app.get("/")
def root():
    return {"peer1_id": anon_id}

@app.get("/test-send")
def test_send():
    plaintext = b"Test message from Render"
    encrypted = encrypt_message(plaintext)  # your logic

    response = requests.post(
        "https://boulder-joyous-bell.glitch.me/receive",
        json={"encrypted_data": encrypted.hex()}
    )
    return {"status": "sent", "glitch_response": response.json()}


@app.get("/exchange")
def exchange_key():
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    res = requests.post(f"{PEER2_URL}/exchange", json={"pub": pem_pub})
    peer_pub = serialization.load_pem_public_key(res.json()['pub'].encode())

    global shared_key
    shared_key = derive_shared_key(private_key, peer_pub)
    return {"message": "Key exchange successful."}

@app.get("/send")
def send_message():
    if not shared_key:
        return {"error": "Key exchange not completed yet."}
    
    msg = "Hello Peer2 from Peer1"
    encrypted = encrypt_message(shared_key, msg)
    b64 = base64.b64encode(encrypted).decode()

    res = requests.post(f"{PEER2_URL}/receive", json={"data": b64})
    return {"peer2_response": res.json()}
