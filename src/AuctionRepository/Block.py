from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import datetime


class Block:

    def __init__(self,previous_hash, amount, signature, username):
        self.username = username
        self.previous_hash = previous_hash
        self.amount = amount
        self.signature = signature
        self.hash = self.build_hash()
        self.timestamp = datetime.datetime.now()


    def build_hash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        data = str(self.previous_hash)+str(self.amount)+str(self.signature)+str(self.username)

        digest.update(data.encode('utf-8'))

        return base64.encodebytes(digest.finalize())

    def getBlockHash(self):
        return self.hash


