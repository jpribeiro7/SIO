import os
from cryptography.hazmat.primitives import serialization
from App.app import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as async_padd
from cryptography.hazmat.primitives import hashes
import cryptography
from cryptography import x509
import base64
from cryptography.hazmat.backends import default_backend

# Verifies the existence of a directory
def check_directory(path):
    if os.path.isdir(path):
        return True
    else:
        return False


# Lists all the files names in the given path
# Returns a tuple with Bool, List of files
# Can also check for the filename and return if _exists
def list_files_dir(path, filename=None):
    if filename is not None:
        _exists = False
        for file in os.listdir(path):
            if file == filename:
                _exists = True
                break
        return _exists, os.listdir(path)
    else:
        return os.listdir(path)


# Saves the recieved key from the server and also the server
# Usage in Client.InitializeSessionKey()
# filename must have '/'
def save_server_key_client(path, content, filename):
    with open(path + filename,"wb+") as file:
        file.write(content)
        file.close()

# Returns the public_bytes of a public key to use in the json message
def get_public_key_bytes(pubkey):
    return pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                               format = serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

# Encript message with session key of a server
def encrypt_message_sk(message, client, address=None):
    if address == AM_ADDRESS or address is None:
        cipher = Cipher(algorithms.AES(client.session_key_manager), modes.CBC(client.session_key_manager[:16]), backend=default_backend())
    else:
        cipher = Cipher(algorithms.AES(client.session_key_repository),
                        modes.CBC(client.session_key_repository[:16]), backend=default_backend())
    temp = None
    if isinstance(message, x509.Certificate):
        temp = message.public_bytes(serialization.Encoding.PEM)
    elif isinstance(message, bytes):
        temp = message
    else:
        temp = message.encode()
    print(temp)
    enc = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    message_enc = b''
    while True:
        if len(temp) < 128:
            message_enc += enc.update(padder.update(temp) + padder.finalize()) + enc.finalize()
            break
        message_enc += enc.update(padder.update(temp[:128]))
        temp = temp[128:]

    return str(base64.b64encode(message_enc), 'utf-8')


#
def unpadd_data(data, session):
    # decipher with the session key
    cipher = Cipher(algorithms.AES(session), modes.CBC(
        session[:16]), backend=default_backend())


    unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
    deciphered = unpadder.update(
        cipher.decryptor().update(base64.b64decode(data)) + cipher.decryptor().finalize()) + unpadder.finalize()

    return deciphered
