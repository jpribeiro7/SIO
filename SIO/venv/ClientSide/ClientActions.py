import os
from venv.ClientSide.Client import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import json

# This class has all the possible messages to comunicate with the server
class ClientActions:

    # Logs in
    # Enter the username and password
    # if it is not the correct password it shall give an error
    # POR ENQUANTO O PROGRAMA CONTINUA NORMALMENTE MESMO ESTANDO ERRADA
    def Login(self):
        message = "{ \"type\" : \"login\","

        print("\n")

        username = input("Insert Username: ")
        password = input("Insert password: ")

        # Username is some information from the cc
        c = Client(username)
        c.set_credentials(username,password)
        # Now establish the session key for secure communication
        c.initialize_session_key()

        # if it exists it wont send its keys
        if c.verify_existence(username):

            try:
                c.load_keys(password)
            except:
                print("Wrong username/password")

            message += "\"username\" : \"" + c.username + "\""

        else:
            # Encript only the public key, since its the only sensitive information atm
            c.set_keys(password)
            pk = c.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
                'utf-8')
            message += "\"username\" : \"" + c.username + "\","
            message += "\"pk\" : \"" + self.encrypt_function(pk,c)+ "\""

        message += " }"

        return message,c


    #TODO
    def create_auction(self,client):
        message = "{ \"type\" : \"create_auction\",\n"
        message += "\"username\" : \""+client.username + "\",\n"

        # double break line
        print("\n\n")
        # Ask for Auction_type : Either Blind or Normal
        # If user is a smarty ask again.
        auc_type = input("Auction type? (B)lind or (N)ormal: ")
        if auc_type.lower() in ["blind", "b"]:
            auc_type = "blind"
        elif auc_type.lower() in ["normal", "n"]:
            auc_type = "normal"
        else:
            self.create_auction(client)

        ### TESTING SIGNATURE
        t = "{\"hello\" : \"himinameisjeff\" ,\n"
        t+= "\"test\" : \"andthisisit\"}"

        message += "\"message\" : \"" + self.encrypt_function(t,client) + "\", \n"
        message += "\"sign\" : \"" + client.sign_message(t) + "\"}"

        print(message)
        return message

    #TODO
    def setBidValidation(self):
        message = "{ \"type\" : \"create_auction\",\n"
        message += "\"???\" : \"" + 777 + "\" }"
        return message

    #TODO
    def terminateAuction(self, client, auction):
        message = "{ \"type\" : \"terminate_auction\",\n"
        message += "\"client\" : \"" + client.id + "\", \n "
        message += "\"auction\" : \"" + auction + "\"}"
        return message

    #TODO
    def bid(self, client, auction, value):
        message = "{ \"type\" : \"bid\",\n"
        message += "\"client\" : \"" + client.id + "\", \n "
        message += "\"auction\" : \"" + auction + "\", \n"
        message += "\"value\" : \"" + value + "\"}"
        return message



    # Function that encrypts the message
    # Client is necessary
    def encrypt_function(self,message, client):
        cipher = Cipher(algorithms.AES(client.session_key), modes.CBC(client.session_key[:16]), backend=default_backend())
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

