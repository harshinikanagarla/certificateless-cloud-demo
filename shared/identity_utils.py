import uuid
import hashlib

def generate_anonymous_id():
    uid = uuid.uuid4().hex
    return hashlib.sha256(uid.encode()).hexdigest()
