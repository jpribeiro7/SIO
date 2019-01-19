import os
from base64 import encode
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
from cryptography.fernet import Fernet

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


# Encrypt message with session key of a server
def encrypt_message_sk(message, session_key):
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(session_key[:16]), backend=default_backend())

    temp = None
    if isinstance(message, x509.Certificate):
        temp = message.public_bytes(serialization.Encoding.PEM)
    elif isinstance(message, bytes):
        temp = message
    else:
        temp = message.encode()
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


# Encrypt with the session key and then with the created key
# Return [key, message, iv]
def encrypt_message_complete(message, session_key, pub_key):
    # Create a symmetric key to be sent to the user
    # The iv has to be sent but doesn't need to be encrypted
    key = Fernet.generate_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv), backend=default_backend())
    # Encrypt with session
    sk_str = encrypt_message_sk(message, session_key)

    sk_enc = base64.b64encode(sk_str.encode("utf-8"))

    # Encrypt with the new symetric key
    enc = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    message_enc = b''
    while True:
        if len(sk_enc) < 128:
            message_enc += enc.update(padder.update(sk_enc) + padder.finalize()) + enc.finalize()
            break
        message_enc += enc.update(padder.update(sk_enc[:128]))
        sk_enc = sk_enc[128:]

    complete_message = str(base64.b64encode(message_enc),"utf-8")

    # Encrypt the key
    enc_key = pub_key.encrypt(key, padding=async_padd.OAEP(
        mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    # Encrypt the iv
    enc_iv = pub_key.encrypt(iv, padding=async_padd.OAEP(
        mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    return [enc_key, complete_message, enc_iv]

# Decryptsd  the data
def decrypt_data(sesssion_key, data, enc_iv, enc_key, private_key):
    # All data must come decoded
    # Decript the key and iv
    key = private_key.decrypt(enc_key,async_padd.OAEP(
        mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    # Decrypt the iv
    iv = private_key.decrypt(enc_iv,async_padd.OAEP(
        mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    # Create the KEY cipher and unpadd
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv), backend=default_backend())
    key_unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = key_unpadder.update(cipher.decryptor().update(
        base64.b64decode(data)) + cipher.decryptor().finalize()) + key_unpadder.finalize()

    plain_text = unpadd_data(base64.b64decode(unpadded_data), sesssion_key)

    return base64.b64decode(plain_text)


# Deciphers the data with the session key
def unpadd_data(data, session):
    # decipher with the session key
    cipher = Cipher(algorithms.AES(session), modes.CBC(
        session[:16]), backend=default_backend())

    unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
    deciphered = unpadder.update(
        cipher.decryptor().update(base64.b64decode(data)) + cipher.decryptor().finalize()) + unpadder.finalize()

    return deciphered

def b_decod(data):
    return base64.b64decode(data)