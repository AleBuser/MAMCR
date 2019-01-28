import json
from ciphers import Ed25519Cipher


class Message:
    def __init__(self, data = None, pubkey = None, signature = None, timestamp = None):
        self.data_payload = data
        self.pubkey = pubkey
        self.signature = signature
        self.timestamp = timestamp

    def set_data_payload(self, data):
        self.data_payload = data

    def set_pubkey(self, pubkey):
        self.pubkey = pubkey.to_ascii(encoding = 'base64').decode()

    def set_signature(self, signature):
        self.signature = signature

    def set_timestamp(self, timestamp):
        self.timestamp = timestamp

    def finalize(self, data: str, extra_data: str, pubkey, prikey,timestamp):
        self.set_data_payload(data)
        self.set_pubkey(pubkey)
        self.set_signature(Ed25519Cipher.sign_message((data + extra_data).encode(), prikey).decode())
        self.set_timestamp(timestamp)
        return self

    def __str__(self):
        return json.dumps(self.__dict__)