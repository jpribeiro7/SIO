import os


#This class has all the information of a client


class Client:

    def __init__(self, username):
        self.id = os.urandom(12)
        self.username = username
        self.credentials = ()

    def set_username(self, username):
        self.username = username

    def set_credentials(self,username, password):
        self.credentials = (username, password)