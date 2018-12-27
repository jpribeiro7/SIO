from AuctionRepository.Auction import Auction
import base64
import os
from AuctionRepository.AuctionRepositoryEntity import AuctionRepositoryEntity
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import codecs
import json
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from AssymetricKeys.RSAKeyGen import RSAKeyGen
from Blockchain.blockchain import BlockChain


class AuctionRepositoryActions:

    def __init__(self, sock):

        self.auction_repository = AuctionRepositoryEntity()
        self.sock = sock
        # Keys creation/ Reload
        self.rsa_keygen = RSAKeyGen()
        if os.path.isdir(os.getcwd() + "/server"):
            self.auction_repository.private_key, self.auction_repository.public_key = self.rsa_keygen.load_key(os.getcwd()
                                                                                                         + "/server")
        else:
            os.mkdir(os.getcwd() + "/server")
            os.mkdir(os.getcwd() + "/auctions")
            self.auction_repository.private_key, self.auction_repository.public_key = self.rsa_keygen.generate_key_pair()
            self.rsa_keygen.save_keys(path=os.getcwd() + "/server")

    # Function to create a session key between user and server
    def create_session_key(self, message_json, address):
        print("creating key")
        # decode the data
        parameters = pickle.loads(codecs.decode(message_json["data"].encode(), "base64"))
        par = load_pem_parameters(parameters, backend=default_backend())

        # Generate our public/private key
        private_key = par.generate_private_key()
        public_key = private_key.public_key()

        # Get the public key from the user
        peer_public_key_bytes = message_json["pk"].encode()
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                           backend=default_backend()).derive(shared_key)

        # Now send our public key to the client
        message = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        # Set the sessionKey as the bytes of the derived_key
        session_key = derived_key

        # Get the username
        self.auction_repository.session_key_clients.append((message_json["username"], session_key))
        sent = self.sock.sendto(base64.b64encode(message.encode('utf-8')), address)

    # Function to create a session key between server and server
    def create_session_key_server(self, message_json, address):
        # decode the data
        parameters = pickle.loads(codecs.decode(message_json["data"].encode(), "base64"))
        par = load_pem_parameters(parameters, backend=default_backend())

        # Generate our public/private key
        private_key = par.generate_private_key()
        public_key = private_key.public_key()

        # Get the public key from the user
        peer_public_key_bytes = message_json["pk"].encode()
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                           backend=default_backend()).derive(shared_key)

        # Now send our public key to the client
        message = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        # Set the sessionKey as the bytes of the derived_key
        self.auction_repository.session_key_server = derived_key

        sent = self.sock.sendto(base64.b64encode(message.encode('utf-8')), address)

    # Creates an auction
    def create_auction(self, message_json, address):
        # get the number of auctions in a dir
        number_auc = len([name for name in os.listdir(os.getcwd()+"/auctions") if os.path.isfile(name)])
        # decode the message and decrypt
        decrypted_message = self.decrypt_function_sk(self.auction_repository.session_key_server, message_json["message"])
        # replace the ' with "
        str_msg = codecs.decode(decrypted_message)
        msg = str_msg.replace("'", "\"")
        # Get as json format
        json_m = json.loads(msg, strict=False)
        new_auction = Auction(++number_auc, json_m["auction_type"], json_m["username"], json_m["max_num_bids"],
                              json_m["min_bid"], json_m["th"])
        b_chain = BlockChain(new_auction.auc_max_bids)
        # TODO get the CC and other stuff! maybe send in the auction_create from the other server
        # TODO how do we save the auction
        b_chain.add(amount=new_auction.auc_min_price_bid, description="Auction", cc="CC", pubkey="CLIENT PUBLIC")

        # Save to a file!
        with open(os.getcwd() + "/auctions/" + str(number_auc)+ ".pickle", 'wb') as handle:
            pickle.dump(b_chain, handle, protocol=pickle.HIGHEST_PROTOCOL)

        # Open the file
        #with open(os.getcwd() + "/auctions/" + str(number_auc)+ ".pickle", 'rb') as handle:
        #    b = pickle.load(handle)

        self.sock.sendto(b"VALID", address)

    # List the auctions
    def list_auctions(self, address):
        message = "Auction List : \n"
        files = os.listdir(os.getcwd()+"/auctions")
        for name in files:
            with open(os.getcwd() + "/auctions/" + name, 'rb') as handle:
                b = pickle.load(handle)
                message += name.replace(".pickle","") + "\n"

        self.sock.sendto(base64.b64encode(message.encode()), address)


    # Decrypt with the session key only!
    def decrypt_function_sk(self, session_key, data):

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(
            session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()

        dec = unpadder.update(
            cipher.decryptor().update(base64.b64decode(data)) + cipher.decryptor().finalize()) + unpadder.finalize()

        return dec
